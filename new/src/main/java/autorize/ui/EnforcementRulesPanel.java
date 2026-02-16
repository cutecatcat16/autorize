package autorize.ui;

import autorize.model.AndOr;
import autorize.model.EnforcementRule;
import autorize.model.EnforcementRuleType;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JToggleButton;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Enforcement detector rules.
 *
 * These rules define what an "enforced" response looks like, so Autorize can label replays as Enforced/Bypassed/Unknown
 * even when status codes are the same.
 */
public final class EnforcementRulesPanel {
  private final List<EnforcementRule> rules;
  private final Supplier<AndOr> modeGetter;
  private final Consumer<AndOr> modeSetter;
  private final Runnable onChange;

  private final JPanel root = new JPanel(new BorderLayout());
  private final JLabel hint = new JLabel(" ");

  private final RulesTableModel model;
  private final JTable table;

  private enum TypeOption {
    STATUS_EQUALS("status_equals", EnforcementRuleType.STATUS_EQUALS),
    HEADERS_CONTAINS("headers_contains", EnforcementRuleType.HEADERS_CONTAINS),
    HEADERS_REGEX("headers_regex", EnforcementRuleType.HEADERS_REGEX),
    BODY_CONTAINS("body_contains", EnforcementRuleType.BODY_CONTAINS),
    BODY_REGEX("body_regex", EnforcementRuleType.BODY_REGEX),
    FULL_CONTAINS("full_contains", EnforcementRuleType.FULL_CONTAINS),
    FULL_REGEX("full_regex", EnforcementRuleType.FULL_REGEX),
    FULL_LENGTH_EQUALS("full_length_equals", EnforcementRuleType.FULL_LENGTH_EQUALS);

    private final String label;
    private final EnforcementRuleType type;

    TypeOption(String label, EnforcementRuleType type) {
      this.label = label;
      this.type = type;
    }

    EnforcementRuleType toType() {
      return type;
    }

    static TypeOption fromType(EnforcementRuleType t) {
      for (TypeOption o : values()) {
        if (o.type == t) return o;
      }
      return STATUS_EQUALS;
    }

    @Override
    public String toString() {
      return label;
    }
  }

  public EnforcementRulesPanel(
      List<EnforcementRule> rules,
      Supplier<AndOr> modeGetter,
      Consumer<AndOr> modeSetter,
      Runnable onChange
  ) {
    this.rules = rules;
    this.modeGetter = modeGetter;
    this.modeSetter = modeSetter;
    this.onChange = onChange == null ? () -> {} : onChange;

    root.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

    JPanel top = new JPanel(new BorderLayout());
    top.add(modeBar(), BorderLayout.NORTH);
    top.add(hintPanel(), BorderLayout.SOUTH);

    this.model = new RulesTableModel();
    this.table = new JTable(model);
    this.table.setFillsViewportHeight(true);
    this.table.setRowSelectionAllowed(true);
    this.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    this.table.setRowHeight(26);

    // Type dropdown editor.
    TableColumn typeCol = table.getColumnModel().getColumn(0);
    JComboBox<TypeOption> typeBox = new JComboBox<>(TypeOption.values());
    typeCol.setCellEditor(new DefaultCellEditor(typeBox));
    typeCol.setPreferredWidth(170);

    // NOT checkbox editor.
    TableColumn notCol = table.getColumnModel().getColumn(1);
    JCheckBox inv = new JCheckBox();
    inv.setHorizontalAlignment(JCheckBox.CENTER);
    notCol.setCellEditor(new DefaultCellEditor(inv));
    notCol.setPreferredWidth(55);
    notCol.setMaxWidth(70);

    table.getColumnModel().getColumn(2).setPreferredWidth(800);

    table.getSelectionModel().addListSelectionListener(e -> {
      if (e.getValueIsAdjusting()) return;
      updateHintFromSelection();
    });

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
      updateHintFromSelection();
    });

    remove.addActionListener(e -> {
      int row = table.getSelectedRow();
      if (row < 0) return;
      model.removeRule(row);
      this.onChange.run();
      updateHintFromSelection();
    });

    root.add(top, BorderLayout.NORTH);
    root.add(new JScrollPane(table), BorderLayout.CENTER);
    root.add(buttons, BorderLayout.SOUTH);

    refresh();
    if (table.getRowCount() > 0) {
      table.getSelectionModel().setSelectionInterval(0, 0);
    }
    updateHintFromSelection();
  }

  public JPanel ui() {
    return root;
  }

  public void refresh() {
    SwingUtilities.invokeLater(() -> {
      model.fireTableDataChanged();
      updateHintFromSelection();
    });
  }

  private JPanel modeBar() {
    JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
    p.add(new JLabel("Mode:"));

    JToggleButton orBtn = new JToggleButton("OR");
    JToggleButton andBtn = new JToggleButton("AND");
    ButtonGroup g = new ButtonGroup();
    g.add(orBtn);
    g.add(andBtn);

    AndOr mode = modeGetter.get();
    if (mode == AndOr.AND) andBtn.setSelected(true);
    else orBtn.setSelected(true);

    orBtn.addActionListener(e -> {
      modeSetter.accept(AndOr.OR);
      onChange.run();
      updateHintFromSelection();
    });
    andBtn.addActionListener(e -> {
      modeSetter.accept(AndOr.AND);
      onChange.run();
      updateHintFromSelection();
    });

    p.add(orBtn);
    p.add(andBtn);
    p.add(new JLabel("  (How multiple rules are combined)"));
    return p;
  }

  private JPanel hintPanel() {
    JPanel p = new JPanel(new BorderLayout());
    hint.setForeground(new Color(90, 90, 90));
    p.setBorder(BorderFactory.createEmptyBorder(6, 0, 6, 0));
    p.add(hint, BorderLayout.CENTER);
    return p;
  }

  private void updateHintFromSelection() {
    int row = table.getSelectedRow();
    if (row < 0 || row >= table.getRowCount()) {
      hint.setText("Add rules to describe what an enforced response looks like (e.g., body contains 'Access denied').");
      hint.setForeground(new Color(90, 90, 90));
      return;
    }

    int modelRow = table.convertRowIndexToModel(row);
    EnforcementRule r = modelRow >= 0 && modelRow < rules.size() ? rules.get(modelRow) : null;
    if (r == null) return;

    String msg = describe(r.type(), r.inverse());
    boolean regexInvalid = isRegexType(r.type()) && !r.content().isEmpty() && r.regex() == null;
    if (regexInvalid) {
      hint.setText(msg + "  (Invalid regex)");
      hint.setForeground(new Color(160, 60, 60));
    } else {
      hint.setText(msg);
      hint.setForeground(new Color(90, 90, 90));
    }
  }

  private static boolean isRegexType(EnforcementRuleType t) {
    return t == EnforcementRuleType.HEADERS_REGEX
        || t == EnforcementRuleType.BODY_REGEX
        || t == EnforcementRuleType.FULL_REGEX;
  }

  private static String describe(EnforcementRuleType t, boolean inverse) {
    String not = inverse ? "NOT " : "";
    return switch (t) {
      case STATUS_EQUALS -> not + "Match when the HTTP status code equals the content (e.g., 401).";
      case HEADERS_CONTAINS -> not + "Match when response headers contain the content substring.";
      case HEADERS_REGEX -> not + "Match when response headers match the regex.";
      case BODY_CONTAINS -> not + "Match when response body contains the content substring.";
      case BODY_REGEX -> not + "Match when response body matches the regex.";
      case FULL_CONTAINS -> not + "Match when full response contains the content substring.";
      case FULL_REGEX -> not + "Match when full response matches the regex.";
      case FULL_LENGTH_EQUALS -> not + "Match when full response byte length equals the content (number).";
    };
  }

  private final class RulesTableModel extends AbstractTableModel {
    private static final int COL_TYPE = 0;
    private static final int COL_NOT = 1;
    private static final int COL_CONTENT = 2;

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
      if (column == COL_NOT) return "NOT";
      if (column == COL_CONTENT) return "Content";
      return "";
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
      if (columnIndex == COL_TYPE) return TypeOption.class;
      if (columnIndex == COL_NOT) return Boolean.class;
      return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
      return true;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
      if (rules == null || rowIndex < 0 || rowIndex >= rules.size()) return "";
      EnforcementRule r = rules.get(rowIndex);
      if (columnIndex == COL_TYPE) return TypeOption.fromType(r.type());
      if (columnIndex == COL_NOT) return r.inverse();
      if (columnIndex == COL_CONTENT) return r.content();
      return "";
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
      if (rules == null || rowIndex < 0 || rowIndex >= rules.size()) return;
      EnforcementRule cur = rules.get(rowIndex);

      EnforcementRuleType type = cur.type();
      boolean inv = cur.inverse();
      String content = cur.content();

      if (columnIndex == COL_TYPE) {
        if (aValue instanceof TypeOption) {
          type = ((TypeOption) aValue).toType();
        }
      } else if (columnIndex == COL_NOT) {
        if (aValue instanceof Boolean) {
          inv = (Boolean) aValue;
        }
      } else if (columnIndex == COL_CONTENT) {
        content = aValue == null ? "" : String.valueOf(aValue);
      }

      rules.set(rowIndex, new EnforcementRule(type, inv, content));
      fireTableRowsUpdated(rowIndex, rowIndex);
      onChange.run();
      updateHintFromSelection();
    }

    int addRule() {
      if (rules == null) return -1;
      rules.add(new EnforcementRule(EnforcementRuleType.BODY_CONTAINS, false, ""));
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

