package autorize.ui;

import autorize.core.AutorizeState;
import autorize.model.InterceptionFilter;
import autorize.model.InterceptionFilterType;

import javax.swing.BorderFactory;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Component;
import java.util.List;

/**
 * Interception filters control which traffic Autorize will process.
 *
 * Semantics are "all filters must pass" (AND). Certain filters are special:
 * - IGNORE_PROXY / IGNORE_TARGET are applied earlier (tool filter).
 * - DROP_PROXY_PORTS is applied by the proxy handler before the HTTP handler sees the request.
 *
 * Note: Project scope is enforced separately in AutorizeController (always-on).
 */
public final class InterceptionFiltersPanel {
  private final AutorizeState state;

  private final JPanel root = new JPanel(new BorderLayout());
  private final JLabel hint = new JLabel(" ");

  private final FiltersTableModel model;
  private final JTable table;

  public InterceptionFiltersPanel(AutorizeState state) {
    this.state = state;

    root.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

    JPanel top = new JPanel(new BorderLayout());
    hint.setForeground(new Color(90, 90, 90));
    hint.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));
    top.add(hint, BorderLayout.CENTER);

    this.model = new FiltersTableModel();
    this.table = new JTable(model);
    this.table.setFillsViewportHeight(true);
    this.table.setRowSelectionAllowed(true);
    this.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    this.table.setRowHeight(26);

    // Type dropdown editor.
    TableColumn typeCol = table.getColumnModel().getColumn(0);
    JComboBox<InterceptionFilterType> typeBox = new JComboBox<>(InterceptionFilterType.values());
    typeCol.setCellEditor(new DefaultCellEditor(typeBox));
    typeCol.setPreferredWidth(190);

    // Content column (inline edit on double-click).
    TableColumn contentCol = table.getColumnModel().getColumn(1);
    contentCol.setPreferredWidth(800);

    // Render newlines as "\n" so the table stays single-line but remains readable.
    contentCol.setCellRenderer(new DefaultTableCellRenderer() {
      @Override
      public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        Object v = value;
        if (v instanceof String) {
          String s = (String) v;
          v = s.replace("\r", "").replace("\n", "\\n");
        }
        return super.getTableCellRendererComponent(table, v, isSelected, hasFocus, row, column);
      }
    });

    table.getSelectionModel().addListSelectionListener(e -> {
      if (e.getValueIsAdjusting()) return;
      updateHintFromSelection();
    });

    JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
    JButton add = new JButton("+");
    JButton remove = new JButton("-");
    JButton up = new JButton("Up");
    JButton down = new JButton("Down");
    buttons.add(add);
    buttons.add(remove);
    buttons.add(up);
    buttons.add(down);

    add.addActionListener(e -> {
      int idx = model.addFilter();
      if (idx >= 0) {
        table.getSelectionModel().setSelectionInterval(idx, idx);
        table.scrollRectToVisible(table.getCellRect(idx, 0, true));
      }
      updateHintFromSelection();
    });

    remove.addActionListener(e -> {
      int row = table.getSelectedRow();
      if (row < 0) return;
      int modelRow = table.convertRowIndexToModel(row);
      model.removeFilter(modelRow);
      updateHintFromSelection();
    });

    up.addActionListener(e -> moveSelected(-1));
    down.addActionListener(e -> moveSelected(+1));

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
      if (table.getSelectedRow() < 0 && table.getRowCount() > 0) {
        table.getSelectionModel().setSelectionInterval(0, 0);
      }
      updateHintFromSelection();
    });
  }

  private void moveSelected(int delta) {
    int row = table.getSelectedRow();
    if (row < 0) return;
    int modelRow = table.convertRowIndexToModel(row);
    int target = modelRow + delta;
    if (target < 0 || target >= state.interceptionFilters().size()) return;
    state.moveInterceptionFilter(modelRow, target);
    refresh();
    int viewTarget = table.convertRowIndexToView(target);
    if (viewTarget >= 0 && viewTarget < table.getRowCount()) {
      table.getSelectionModel().setSelectionInterval(viewTarget, viewTarget);
      table.scrollRectToVisible(table.getCellRect(viewTarget, 0, true));
    }
  }

  private void updateHintFromSelection() {
    int row = table.getSelectedRow();
    if (row < 0 || row >= table.getRowCount()) {
      hint.setText("All filters must pass for Autorize to process a request. Project scope is always enforced.");
      hint.setForeground(new Color(90, 90, 90));
      return;
    }

    int modelRow = table.convertRowIndexToModel(row);
    List<InterceptionFilter> fs = state.interceptionFilters();
    InterceptionFilter f = modelRow >= 0 && modelRow < fs.size() ? fs.get(modelRow) : null;
    if (f == null) return;

    String msg = describe(f.type());
    boolean regexInvalid = isRegexType(f.type()) && !f.content().isEmpty() && f.regex() == null;
    if (regexInvalid) {
      hint.setText(msg + "  (Invalid regex)");
      hint.setForeground(new Color(160, 60, 60));
    } else {
      hint.setText(msg);
      hint.setForeground(new Color(90, 90, 90));
    }
  }

  private static boolean isRegexType(InterceptionFilterType t) {
    return t == InterceptionFilterType.URL_REGEX
        || t == InterceptionFilterType.URL_NOT_REGEX
        || t == InterceptionFilterType.REQ_BODY_REGEX
        || t == InterceptionFilterType.REQ_BODY_NOT_REGEX
        || t == InterceptionFilterType.RES_BODY_REGEX
        || t == InterceptionFilterType.RES_BODY_NOT_REGEX;
  }

  private static String describe(InterceptionFilterType t) {
    return switch (t) {
      case SCOPE_ONLY -> "Project scope is always enforced; this row is optional and acts as an extra guard.";
      case URL_CONTAINS -> "Pass when request URL contains the substring.";
      case URL_REGEX -> "Pass when request URL matches the regex.";
      case URL_NOT_CONTAINS -> "Pass when request URL does NOT contain the substring.";
      case URL_NOT_REGEX -> "Pass when request URL does NOT match the regex.";
      case REQ_BODY_CONTAINS -> "Pass when request body contains the substring.";
      case REQ_BODY_REGEX -> "Pass when request body matches the regex.";
      case REQ_BODY_NOT_CONTAINS -> "Pass when request body does NOT contain the substring.";
      case REQ_BODY_NOT_REGEX -> "Pass when request body does NOT match the regex.";
      case RES_BODY_CONTAINS -> "Pass when response body contains the substring.";
      case RES_BODY_REGEX -> "Pass when response body matches the regex.";
      case RES_BODY_NOT_CONTAINS -> "Pass when response body does NOT contain the substring.";
      case RES_BODY_NOT_REGEX -> "Pass when response body does NOT match the regex.";
      case REQ_HEADER_CONTAINS -> "Pass when any request header line contains the substring.";
      case REQ_HEADER_NOT_CONTAINS -> "Pass when no request header line contains the substring.";
      case RES_HEADER_CONTAINS -> "Pass when any response header line contains the substring.";
      case RES_HEADER_NOT_CONTAINS -> "Pass when no response header line contains the substring.";
      case ONLY_METHODS -> "Pass when HTTP method is in the list (comma- or newline-separated, e.g., GET,POST).";
      case IGNORE_METHODS -> "Pass when HTTP method is NOT in the list (comma- or newline-separated).";
      case IGNORE_OPTIONS -> "Drop OPTIONS from processing.";
      case IGNORE_PROXY -> "Ignore traffic coming from Proxy tool.";
      case IGNORE_TARGET -> "Ignore traffic coming from Target tool.";
      case DROP_PROXY_PORTS -> "Drop requests that arrive via specific proxy listener ports (comma-separated, e.g., 8080,8443).";
    };
  }

  private final class FiltersTableModel extends AbstractTableModel {
    private static final int COL_TYPE = 0;
    private static final int COL_CONTENT = 1;

    @Override
    public int getRowCount() {
      return state.interceptionFilters() == null ? 0 : state.interceptionFilters().size();
    }

    @Override
    public int getColumnCount() {
      return 2;
    }

    @Override
    public String getColumnName(int column) {
      if (column == COL_TYPE) return "Type";
      if (column == COL_CONTENT) return "Content";
      return "";
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
      if (columnIndex == COL_TYPE) return InterceptionFilterType.class;
      return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
      return true;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
      List<InterceptionFilter> fs = state.interceptionFilters();
      if (fs == null || rowIndex < 0 || rowIndex >= fs.size()) return "";
      InterceptionFilter f = fs.get(rowIndex);
      if (columnIndex == COL_TYPE) return f.type();
      if (columnIndex == COL_CONTENT) return f.content();
      return "";
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
      List<InterceptionFilter> fs = state.interceptionFilters();
      if (fs == null || rowIndex < 0 || rowIndex >= fs.size()) return;
      InterceptionFilter cur = fs.get(rowIndex);
      InterceptionFilterType t = cur.type();
      String c = cur.content();

      if (columnIndex == COL_TYPE) {
        if (aValue instanceof InterceptionFilterType) {
          t = (InterceptionFilterType) aValue;
        }
      } else if (columnIndex == COL_CONTENT) {
        c = aValue == null ? "" : String.valueOf(aValue);
      }

      state.updateInterceptionFilter(rowIndex, new InterceptionFilter(t, c));
      fireTableRowsUpdated(rowIndex, rowIndex);
      updateHintFromSelection();
    }

    int addFilter() {
      state.addInterceptionFilter(new InterceptionFilter(InterceptionFilterType.URL_CONTAINS, ""));
      return state.interceptionFilters().size() - 1;
    }

    void removeFilter(int rowIndex) {
      state.removeInterceptionFilter(rowIndex);
      fireTableDataChanged();
    }
  }
}
