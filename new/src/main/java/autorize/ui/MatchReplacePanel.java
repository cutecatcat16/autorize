package autorize.ui;

import autorize.model.MatchReplaceRule;
import autorize.model.MatchReplaceType;

import javax.swing.BorderFactory;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.List;

/**
 * Table-based Match/Replace editor.
 *
 * Each row is one rule applied to the replayed ("modified") request before sending.
 */
public final class MatchReplacePanel {
  private static final String DEFAULT_STEPPER_HEADER = "X-Stepper-Execute-Login";

  private final List<MatchReplaceRule> rules;
  private final Runnable onChange;

  private final JPanel root = new JPanel(new BorderLayout());

  private final MatchReplaceTableModel model;
  private final JTable table;

  private enum TypeOption {
    HEADER_REPLACE("header_replace", MatchReplaceType.HEADER_REPLACE),
    COOKIE_REPLACE("cookie_replace", MatchReplaceType.COOKIE_REPLACE),
    STEPPER_HEADER("stepper_header", MatchReplaceType.STEPPER_HEADER),
    BODY_REGEX("body_regex", MatchReplaceType.BODY_REGEX),
    PATH_REGEX("path_regex", MatchReplaceType.PATH_REGEX);

    private final String label;
    private final MatchReplaceType type;

    TypeOption(String label, MatchReplaceType type) {
      this.label = label;
      this.type = type;
    }

    MatchReplaceType toType() {
      return type;
    }

    static TypeOption fromType(MatchReplaceType type) {
      if (type == MatchReplaceType.HEADER_REPLACE) return HEADER_REPLACE;
      if (type == MatchReplaceType.COOKIE_REPLACE) return COOKIE_REPLACE;
      if (type == MatchReplaceType.STEPPER_HEADER) return STEPPER_HEADER;
      if (type == MatchReplaceType.BODY_REGEX) return BODY_REGEX;
      if (type == MatchReplaceType.PATH_REGEX) return PATH_REGEX;
      // Backward compatibility for legacy configs that used old header modes.
      if (type == MatchReplaceType.HEADERS_REGEX || type == MatchReplaceType.HEADERS_SIMPLE) return HEADER_REPLACE;
      return HEADER_REPLACE;
    }

    @Override
    public String toString() {
      return label;
    }
  }

  public MatchReplacePanel(List<MatchReplaceRule> rules, Runnable onChange) {
    this.rules = rules;
    this.onChange = onChange == null ? () -> {} : onChange;

    root.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

    this.model = new MatchReplaceTableModel();
    this.table = new JTable(model);
    this.table.setFillsViewportHeight(true);
    this.table.setRowSelectionAllowed(true);
    this.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

    // Type dropdown editor.
    TableColumn typeCol = table.getColumnModel().getColumn(0);
    JComboBox<TypeOption> typeBox = new JComboBox<>(TypeOption.values());
    typeCol.setCellEditor(new DefaultCellEditor(typeBox));
    typeCol.setPreferredWidth(140);
    table.getColumnModel().getColumn(1).setPreferredWidth(420);
    table.getColumnModel().getColumn(2).setPreferredWidth(420);

    JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
    JButton add = new JButton("+");
    JButton remove = new JButton("-");
    buttons.add(add);
    buttons.add(remove);

    add.addActionListener(e -> {
      int idx = model.addRule();
      if (idx >= 0) {
        table.getSelectionModel().setSelectionInterval(idx, idx);
        table.scrollRectToVisible(table.getCellRect(idx, 0, true));
      }
      this.onChange.run();
    });

    remove.addActionListener(e -> {
      int row = table.getSelectedRow();
      if (row < 0) return;
      model.removeRule(row);
      this.onChange.run();
    });

    root.add(buttons, BorderLayout.NORTH);
    root.add(new JScrollPane(table), BorderLayout.CENTER);
  }

  public JPanel ui() {
    return root;
  }

  private final class MatchReplaceTableModel extends AbstractTableModel {
    private static final int COL_TYPE = 0;
    private static final int COL_MATCH = 1;
    private static final int COL_REPLACE = 2;

    @Override
    public int getRowCount() {
      return rules == null ? 0 : rules.size();
    }

    @Override
    public int getColumnCount() {
      return 3;
    }

    @Override
    public String getColumnName(int column) {
      if (column == COL_TYPE) return "Type";
      if (column == COL_MATCH) return "Match";
      if (column == COL_REPLACE) return "Replace";
      return "";
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
      if (columnIndex == COL_TYPE) return TypeOption.class;
      return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
      return true;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
      if (rules == null || rowIndex < 0 || rowIndex >= rules.size()) return "";
      MatchReplaceRule r = rules.get(rowIndex);
      if (columnIndex == COL_TYPE) return TypeOption.fromType(r.type());
      if (columnIndex == COL_MATCH) {
        if (r.type() == MatchReplaceType.STEPPER_HEADER) return DEFAULT_STEPPER_HEADER;
        return r.match();
      }
      if (columnIndex == COL_REPLACE) return r.replace();
      return "";
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
      if (rules == null || rowIndex < 0 || rowIndex >= rules.size()) return;
      MatchReplaceRule cur = rules.get(rowIndex);

      MatchReplaceType type = cur.type();
      String match = cur.match();
      String replace = cur.replace();

      if (columnIndex == COL_TYPE) {
        if (aValue instanceof TypeOption) {
          type = ((TypeOption) aValue).toType();
        } else if (aValue != null) {
          type = TypeOption.fromType(type).toType();
        }
        if (type == MatchReplaceType.STEPPER_HEADER) {
          match = DEFAULT_STEPPER_HEADER;
        }
      } else if (columnIndex == COL_MATCH) {
        if (type == MatchReplaceType.STEPPER_HEADER) {
          match = DEFAULT_STEPPER_HEADER;
        } else {
          match = aValue == null ? "" : String.valueOf(aValue);
        }
      } else if (columnIndex == COL_REPLACE) {
        replace = aValue == null ? "" : String.valueOf(aValue);
      }

      rules.set(rowIndex, new MatchReplaceRule(type, match, replace));
      fireTableRowsUpdated(rowIndex, rowIndex);
      onChange.run();
    }

    int addRule() {
      if (rules == null) return -1;
      rules.add(new MatchReplaceRule(MatchReplaceType.HEADER_REPLACE, "", ""));
      int idx = rules.size() - 1;
      fireTableRowsInserted(idx, idx);
      return idx;
    }

    void removeRule(int rowIndex) {
      if (rules == null) return;
      if (rowIndex < 0 || rowIndex >= rules.size()) return;
      rules.remove(rowIndex);
      fireTableDataChanged();
    }
  }
}
