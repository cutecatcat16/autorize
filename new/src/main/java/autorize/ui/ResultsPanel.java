package autorize.ui;

import autorize.core.AutorizeState;
import autorize.model.LogEntry;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.SortOrder;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

public final class ResultsPanel {
  private final MontoyaApi api;
  private final AutorizeState state;

  private final JPanel root = new JPanel(new BorderLayout());

  private final ResultsTableModel model;
  private final JTable table;
  private final TableRowSorter<ResultsTableModel> sorter;

  private final JTextField filterText = new JTextField(26);
  private final JCheckBox filterBypassed = new JCheckBox("Bypassed");
  private final JCheckBox filterEnforced = new JCheckBox("Enforced");
  private final JCheckBox filterUnknown = new JCheckBox("Is enforced???");

  // Focused-mode toggle. OFF = show all editors in order, ON = show only the current context pair.
  private final JToggleButton expand = new JToggleButton("Expand");

  private final JTabbedPane detailsTabs = new JTabbedPane();

  private HttpRequestEditor originalReqEditor;
  private HttpResponseEditor originalResEditor;
  private HttpRequestEditor unauthReqEditor;
  private HttpResponseEditor unauthResEditor;

  private final Map<UUID, HttpRequestEditor> profileReqEditors = new LinkedHashMap<>();
  private final Map<UUID, HttpResponseEditor> profileResEditors = new LinkedHashMap<>();

  private enum ContextType { ORIGINAL, MODIFIED, UNAUTH }
  private volatile ContextType lastContextType = ContextType.ORIGINAL;
  private volatile UUID lastContextProfileId = null;

  private final JPopupMenu popup = new JPopupMenu();
  private final JMenuItem sendToRepeater = new JMenuItem("Send Request to Repeater");
  private final JMenuItem sendToComparer = new JMenuItem("Send Responses to Comparer");
  private final JMenuItem retestSelected = new JMenuItem("Retest selected request");
  private final JMenuItem retestAll = new JMenuItem("Retest all requests");
  private final JMenuItem copyUrl = new JMenuItem("Copy URL");
  private final JMenuItem deleteRows = new JMenuItem("Delete Selected Rows");

  private volatile Consumer<List<Integer>> retestSelectedHandler = null;
  private volatile Runnable retestAllHandler = null;

  public ResultsPanel(MontoyaApi api, AutorizeState state) {
    this.api = api;
    this.state = state;
    this.model = new ResultsTableModel(state);
    this.table = new JTable(model);
    this.sorter = new TableRowSorter<>(model);

    this.table.setFillsViewportHeight(true);
    this.table.setRowSelectionAllowed(true);
    this.table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
    // Legacy-like behavior: keep widths stable and allow horizontal scroll for many user columns.
    this.table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
    this.table.setRowSorter(sorter);
    applyDefaultSort();

    this.table.getSelectionModel().addListSelectionListener(this::onRowSelected);
    this.table.addMouseListener(new MouseAdapter() {
      @Override
      public void mousePressed(MouseEvent e) { maybeShowPopup(e); }

      @Override
      public void mouseReleased(MouseEvent e) { maybeShowPopup(e); }

      @Override
      public void mouseClicked(MouseEvent e) {
        if (!e.isPopupTrigger() && e.getButton() == MouseEvent.BUTTON1) {
          onCellClicked();
        }
      }
    });

    popup.add(sendToRepeater);
    popup.add(sendToComparer);
    popup.addSeparator();
    popup.add(retestSelected);
    popup.add(retestAll);
    popup.add(copyUrl);
    popup.addSeparator();
    popup.add(deleteRows);

    sendToRepeater.addActionListener(e -> doSendToRepeater());
    sendToComparer.addActionListener(e -> doSendToComparer());
    retestSelected.addActionListener(e -> doRetestSelected());
    retestAll.addActionListener(e -> doRetestAll());
    copyUrl.addActionListener(e -> copySelectedUrlToClipboard());
    deleteRows.addActionListener(e -> doDeleteSelectedRows());

    // Keyboard delete for row deletion.
    this.table.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "autorizeDeleteRows");
    this.table.getActionMap().put("autorizeDeleteRows", new AbstractAction() {
      @Override
      public void actionPerformed(ActionEvent e) { doDeleteSelectedRows(); }
    });

    // Legacy-style shortcuts on the table (Cmd/Ctrl+R and Cmd/Ctrl+C).
    int menuMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
    this.table.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_R, menuMask), "autorizeSendToRepeater");
    this.table.getActionMap().put("autorizeSendToRepeater", new AbstractAction() {
      @Override
      public void actionPerformed(ActionEvent e) { doSendToRepeater(); }
    });
    this.table.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_C, menuMask), "autorizeCopyUrl");
    this.table.getActionMap().put("autorizeCopyUrl", new AbstractAction() {
      @Override
      public void actionPerformed(ActionEvent e) { copySelectedUrlToClipboard(); }
    });

    JPanel editors = new JPanel(new BorderLayout());
    editors.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

    // Many tabs: keep them on a single row with left/right scroll arrows (legacy-like).
    detailsTabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);

    JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
    bar.add(new JLabel("Filter:"));
    bar.add(filterText);
    bar.add(filterBypassed);
    bar.add(filterEnforced);
    bar.add(filterUnknown);
    bar.add(new JLabel("  "));
    bar.add(expand);

    filterText.getDocument().addDocumentListener(new SimpleDocumentListener(this::applyFilters));
    filterBypassed.addActionListener(e -> {
      state.setShowBypassed(filterBypassed.isSelected());
      applyFilters();
    });
    filterEnforced.addActionListener(e -> {
      state.setShowEnforced(filterEnforced.isSelected());
      applyFilters();
    });
    filterUnknown.addActionListener(e -> {
      state.setShowUnknown(filterUnknown.isSelected());
      applyFilters();
    });
    expand.addActionListener(e -> rebuildDetailsTabs());

    editors.add(bar, BorderLayout.NORTH);
    editors.add(detailsTabs, BorderLayout.CENTER);

    JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    mainSplit.setResizeWeight(0.50);
    mainSplit.setTopComponent(new JScrollPane(table));
    mainSplit.setBottomComponent(editors);
    root.add(mainSplit, BorderLayout.CENTER);
    // JSplitPane divider proportional position is only meaningful after layout.
    // Set it once on the first resize to get a reliable 50/50 default on load.
    final ComponentAdapter[] once = new ComponentAdapter[1];
    once[0] = new ComponentAdapter() {
      private boolean done = false;

      @Override
      public void componentResized(ComponentEvent e) {
        if (done) return;
        if (mainSplit.getHeight() <= 0) return;
        done = true;
        mainSplit.setDividerLocation(0.50);
        mainSplit.removeComponentListener(once[0]);
      }
    };
    mainSplit.addComponentListener(once[0]);

    filterBypassed.setSelected(state.showBypassed());
    filterEnforced.setSelected(state.showEnforced());
    filterUnknown.setSelected(state.showUnknown());

    this.table.setDefaultRenderer(Object.class, new VerdictRenderer());

    initEditors();
    rebuildDetailsTabs();
  }

  public JPanel ui() {
    return root;
  }

  public void setRetestHandlers(Consumer<List<Integer>> retestSelectedHandler, Runnable retestAllHandler) {
    this.retestSelectedHandler = retestSelectedHandler;
    this.retestAllHandler = retestAllHandler;
  }

  public void refreshProfiles() {
    SwingUtilities.invokeLater(() -> {
      model.fireTableStructureChanged();
      applyDefaultSort();
      updateColumnWidths();
      applyFilters();

      rebuildProfileEditors();
      rebuildDetailsTabs();
      refreshEditors();
    });
  }

  public void refreshLog() {
    SwingUtilities.invokeLater(() -> {
      model.fireTableDataChanged();
      applyDefaultSort();
      updateColumnWidths();
      applyFilters();

      if (state.autoScroll() && table.getRowCount() > 0) {
        // With default sorting (# DESC), newest entry is at the top.
        int first = 0;
        table.getSelectionModel().setSelectionInterval(first, first);
        table.scrollRectToVisible(table.getCellRect(first, 0, true));
      }

      refreshEditors();
    });
  }

  private void onRowSelected(ListSelectionEvent e) {
    if (e.getValueIsAdjusting()) return;
    refreshEditors();
  }

  private void initEditors() {
    originalReqEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
    originalResEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
    unauthReqEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
    unauthResEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
    rebuildProfileEditors();
  }

  private void rebuildProfileEditors() {
    profileReqEditors.clear();
    profileResEditors.clear();
    for (UUID id : state.profileNamesSnapshot().keySet()) {
      profileReqEditors.put(id, api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY));
      profileResEditors.put(id, api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY));
    }
  }

  private void rebuildDetailsTabs() {
    if (originalReqEditor == null) return;
    detailsTabs.removeAll();

    if (!expand.isSelected()) {
      // Show everything in order: Original, Unauth, then each user.
      detailsTabs.addTab("Original Request", originalReqEditor.uiComponent());
      detailsTabs.addTab("Original Response", originalResEditor.uiComponent());
      detailsTabs.addTab("Unauth Request", unauthReqEditor.uiComponent());
      detailsTabs.addTab("Unauth Response", unauthResEditor.uiComponent());

      Map<UUID, String> profiles = state.profileNamesSnapshot();
      for (UUID id : profiles.keySet()) {
        String name = profiles.get(id);
        HttpRequestEditor reqEd = profileReqEditors.get(id);
        HttpResponseEditor resEd = profileResEditors.get(id);
        if (reqEd != null) detailsTabs.addTab(name + " Request", reqEd.uiComponent());
        if (resEd != null) detailsTabs.addTab(name + " Response", resEd.uiComponent());
      }
      return;
    }

    // Focused mode: only the selected context pair.
    if (lastContextType == ContextType.ORIGINAL) {
      detailsTabs.addTab("Original Request", originalReqEditor.uiComponent());
      detailsTabs.addTab("Original Response", originalResEditor.uiComponent());
      return;
    }
    if (lastContextType == ContextType.UNAUTH) {
      detailsTabs.addTab("Unauth Request", unauthReqEditor.uiComponent());
      detailsTabs.addTab("Unauth Response", unauthResEditor.uiComponent());
      return;
    }

    UUID id = lastContextProfileId;
    if (id == null) {
      id = state.profileNamesSnapshot().keySet().stream().findFirst().orElse(null);
    }
    String name = id == null ? "User" : state.profileNamesSnapshot().getOrDefault(id, "User");
    HttpRequestEditor reqEd = id == null ? null : profileReqEditors.get(id);
    HttpResponseEditor resEd = id == null ? null : profileResEditors.get(id);
    if (reqEd != null) detailsTabs.addTab(name + " Request", reqEd.uiComponent());
    if (resEd != null) detailsTabs.addTab(name + " Response", resEd.uiComponent());
  }

  private void refreshEditors() {
    if (originalReqEditor == null) return;
    int row = table.getSelectedRow();
    if (row < 0) return;

    int modelRow = table.convertRowIndexToModel(row);
    List<LogEntry> log = state.logSnapshot();
    if (modelRow < 0 || modelRow >= log.size()) return;
    LogEntry entry = log.get(modelRow);

    HttpRequestResponse original = entry.original();
    if (original != null) {
      originalReqEditor.setRequest(original.request());
      if (original.hasResponse() && original.response() != null) {
        originalResEditor.setResponse(original.response());
      }
    }

    HttpRequestResponse unauth = entry.unauthenticated();
    if (unauth != null) {
      unauthReqEditor.setRequest(unauth.request());
      if (unauth.hasResponse() && unauth.response() != null) {
        unauthResEditor.setResponse(unauth.response());
      }
    }

    for (UUID id : state.profileNamesSnapshot().keySet()) {
      HttpRequestEditor reqEd = profileReqEditors.get(id);
      HttpResponseEditor resEd = profileResEditors.get(id);
      if (reqEd == null || resEd == null) continue;
      HttpRequestResponse rr = entry.perProfile().get(id);
      if (rr == null) continue;
      reqEd.setRequest(rr.request());
      if (rr.hasResponse() && rr.response() != null) {
        resEd.setResponse(rr.response());
      }
    }
  }

  private void applyFilters() {
    final String q = filterText.getText() == null ? "" : filterText.getText().trim().toLowerCase();
    final boolean allowBypassed = filterBypassed.isSelected();
    final boolean allowEnforced = filterEnforced.isSelected();
    final boolean allowUnknown = filterUnknown.isSelected();

    sorter.setRowFilter(new javax.swing.RowFilter<>() {
      @Override
      public boolean include(Entry<? extends ResultsTableModel, ? extends Integer> entry) {
        int row = entry.getIdentifier();
        List<LogEntry> log = state.logSnapshot();
        if (row < 0 || row >= log.size()) return true;
        LogEntry e = log.get(row);

        String url = e.url() == null ? "" : e.url();
        if (!q.isEmpty() && !url.toLowerCase().contains(q)) {
          return false;
        }

        if (allowBypassed && allowEnforced && allowUnknown) return true;
        if ("Disabled".equals(e.unauthVerdict())) return true;

        if (statusMatches(e.unauthVerdict(), allowBypassed, allowUnknown, allowEnforced)) return true;
        for (String v : e.perProfileVerdict().values()) {
          if (statusMatches(v, allowBypassed, allowUnknown, allowEnforced)) return true;
        }
        return false;
      }
    });
  }

  private void updateColumnWidths() {
    if (table.getColumnCount() == 0) return;
    try {
      table.getColumnModel().getColumn(0).setPreferredWidth(50);  // #
      table.getColumnModel().getColumn(1).setPreferredWidth(520); // URL
      table.getColumnModel().getColumn(2).setPreferredWidth(80);  // orig len
      table.getColumnModel().getColumn(3).setPreferredWidth(90);  // unauth len
      table.getColumnModel().getColumn(4).setPreferredWidth(140); // unauth status
      for (int i = 5; i < table.getColumnCount(); i += 2) {
        table.getColumnModel().getColumn(i).setPreferredWidth(90);
        if (i + 1 < table.getColumnCount()) {
          table.getColumnModel().getColumn(i + 1).setPreferredWidth(140);
        }
      }
    } catch (Exception ignored) {
    }
  }

  private void applyDefaultSort() {
    sorter.setSortKeys(Collections.singletonList(new javax.swing.RowSorter.SortKey(0, SortOrder.DESCENDING)));
    sorter.sort();
  }

  private void onCellClicked() {
    int viewRow = table.getSelectedRow();
    int viewCol = table.getSelectedColumn();
    if (viewRow < 0 || viewCol < 0) return;

    int modelCol = table.convertColumnIndexToModel(viewCol);

    if (modelCol == 1 || modelCol == 2) {
      lastContextType = ContextType.ORIGINAL;
      lastContextProfileId = null;
      if (expand.isSelected()) {
        rebuildDetailsTabs();
      }
      refreshEditors();
      return;
    }

    if (modelCol == 3 || modelCol == 4) {
      lastContextType = ContextType.UNAUTH;
      lastContextProfileId = null;
      if (expand.isSelected()) {
        rebuildDetailsTabs();
      }
      refreshEditors();
      return;
    }

    if (modelCol >= 5) {
      int idx = modelCol - 5;
      int userIdx = idx / 2;
      lastContextType = ContextType.MODIFIED;
      lastContextProfileId = profileIdByIndex(userIdx);
      if (expand.isSelected()) {
        rebuildDetailsTabs();
      }
      refreshEditors();
    }
  }

  private UUID profileIdByIndex(int userIdx) {
    if (userIdx < 0) return null;
    int i = 0;
    for (UUID id : state.profileNamesSnapshot().keySet()) {
      if (i == userIdx) return id;
      i++;
    }
    return null;
  }

  private void maybeShowPopup(MouseEvent e) {
    if (!e.isPopupTrigger()) return;
    int row = table.rowAtPoint(e.getPoint());
    int col = table.columnAtPoint(e.getPoint());
    if (row >= 0 && col >= 0) {
      table.setRowSelectionInterval(row, row);
      table.setColumnSelectionInterval(col, col);
      onCellClicked();
    }
    updatePopupText();
    popup.show(e.getComponent(), e.getX(), e.getY());
  }

  private void updatePopupText() {
    String ctxName = currentContextName();
    sendToRepeater.setText("Send " + ctxName + " Request to Repeater");
    sendToComparer.setText("Send " + ctxName + " Responses to Comparer");
  }

  private String currentContextName() {
    if (lastContextType == ContextType.ORIGINAL) return "Original";
    if (lastContextType == ContextType.UNAUTH) return "Unauthenticated";
    UUID id = lastContextProfileId;
    if (id == null) return "Modified";
    var p = state.profileById(id);
    return p == null ? "Modified" : p.name();
  }

  private HttpRequestResponse selectedOriginal() {
    int viewRow = table.getSelectedRow();
    if (viewRow < 0) return null;
    int modelRow = table.convertRowIndexToModel(viewRow);
    List<LogEntry> log = state.logSnapshot();
    if (modelRow < 0 || modelRow >= log.size()) return null;
    return log.get(modelRow).original();
  }

  private HttpRequestResponse selectedUnauth() {
    int viewRow = table.getSelectedRow();
    if (viewRow < 0) return null;
    int modelRow = table.convertRowIndexToModel(viewRow);
    List<LogEntry> log = state.logSnapshot();
    if (modelRow < 0 || modelRow >= log.size()) return null;
    return log.get(modelRow).unauthenticated();
  }

  private HttpRequestResponse currentContextRequestResponse() {
    int viewRow = table.getSelectedRow();
    if (viewRow < 0) return null;
    int modelRow = table.convertRowIndexToModel(viewRow);
    List<LogEntry> log = state.logSnapshot();
    if (modelRow < 0 || modelRow >= log.size()) return null;
    LogEntry e = log.get(modelRow);

    if (lastContextType == ContextType.UNAUTH) return e.unauthenticated();
    if (lastContextType == ContextType.ORIGINAL) return e.original();

    UUID id = lastContextProfileId;
    if (id == null) {
      id = state.profileNamesSnapshot().keySet().stream().findFirst().orElse(null);
    }
    return id == null ? null : e.perProfile().get(id);
  }

  private void doSendToRepeater() {
    HttpRequestResponse rr = currentContextRequestResponse();
    if (rr == null) return;
    String name = currentContextName();
    api.repeater().sendToRepeater(rr.request(), "Autorize: " + name);
  }

  private void doSendToComparer() {
    HttpRequestResponse original = selectedOriginal();
    HttpRequestResponse other = currentContextRequestResponse();
    HttpRequestResponse unauth = selectedUnauth();
    if (original == null) return;

    if (original.response() != null) {
      api.comparer().sendToComparer(original.response().toByteArray());
    }
    if (other != null && other.response() != null) {
      api.comparer().sendToComparer(other.response().toByteArray());
    }
    if (unauth != null && unauth.response() != null) {
      api.comparer().sendToComparer(unauth.response().toByteArray());
    }
  }

  private void doRetestSelected() {
    Consumer<List<Integer>> h = retestSelectedHandler;
    if (h == null) return;

    int[] viewRows = table.getSelectedRows();
    if (viewRows == null || viewRows.length == 0) return;
    List<Integer> modelRows = new ArrayList<>();
    for (int r : viewRows) {
      modelRows.add(table.convertRowIndexToModel(r));
    }
    h.accept(modelRows);
  }

  private void doRetestAll() {
    Runnable h = retestAllHandler;
    if (h == null) return;
    h.run();
  }

  private void doDeleteSelectedRows() {
    int[] viewRows = table.getSelectedRows();
    if (viewRows == null || viewRows.length == 0) return;
    List<Integer> modelRows = new ArrayList<>();
    for (int r : viewRows) {
      modelRows.add(table.convertRowIndexToModel(r));
    }
    state.removeLogRows(modelRows);
  }

  private void copySelectedUrlToClipboard() {
    int viewRow = table.getSelectedRow();
    if (viewRow < 0) return;
    int modelRow = table.convertRowIndexToModel(viewRow);
    List<LogEntry> log = state.logSnapshot();
    if (modelRow < 0 || modelRow >= log.size()) return;

    String url = log.get(modelRow).url();
    if (url == null) url = "";

    try {
      Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url), null);
    } catch (Exception ignored) {
    }
  }

  private boolean statusMatches(String status, boolean allowBypassed, boolean allowUnknown, boolean allowEnforced) {
    if (status == null) return false;
    if (status.contains("Bypassed")) return allowBypassed;
    if (status.contains("Is enforced")) return allowUnknown;
    if (status.contains("Enforced")) return allowEnforced;
    return false;
  }

  private final class VerdictRenderer extends DefaultTableCellRenderer {
    private final Color BYPASSED_TINT = new Color(255, 153, 153);
    private final Color UNKNOWN_TINT = new Color(255, 204, 153);
    private final Color ENFORCED_TINT = new Color(204, 255, 153);
    private final Color DISABLED_TINT = new Color(211, 211, 211);

    @Override
    public java.awt.Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
      super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

      int modelCol = table.convertColumnIndexToModel(column);
      boolean isStatusCol = modelCol == 4 || (modelCol >= 5 && ((modelCol - 5) % 2 == 1));

      Color baseBg = table.getBackground();
      Color baseFg = table.getForeground();
      if (!isSelected) {
        setForeground(baseFg);
        setBackground(baseBg);
      }

      if (!isSelected && isStatusCol) {
        String s = value == null ? "" : value.toString();
        float alpha = isDark(baseBg) ? 0.35f : 0.55f;
        if (s.contains("Bypassed")) setBackground(blend(baseBg, BYPASSED_TINT, alpha));
        else if (s.contains("Is enforced")) setBackground(blend(baseBg, UNKNOWN_TINT, alpha));
        else if (s.contains("Enforced")) setBackground(blend(baseBg, ENFORCED_TINT, alpha));
        else if (s.equals("Disabled")) setBackground(blend(baseBg, DISABLED_TINT, alpha));
      }

      // Mask lengths/statuses based on filter checkboxes like legacy.
      if (!isSelected) {
        boolean allowBypassed = filterBypassed.isSelected();
        boolean allowEnforced = filterEnforced.isSelected();
        boolean allowUnknown = filterUnknown.isSelected();
        if (!(allowBypassed && allowEnforced && allowUnknown)) {
          if (modelCol == 3) {
            int unauthStatusView = table.convertColumnIndexToView(4);
            String st = String.valueOf(table.getValueAt(row, unauthStatusView));
            if (!statusMatches(st, allowBypassed, allowUnknown, allowEnforced) && !"Disabled".equals(st)) {
              setText("");
              setForeground(baseFg);
              setBackground(baseBg);
            }
          } else if (isStatusCol) {
            String st = value == null ? "" : value.toString();
            if (!statusMatches(st, allowBypassed, allowUnknown, allowEnforced) && !"Disabled".equals(st)) {
              setText("");
              setForeground(baseFg);
              setBackground(baseBg);
            }
          } else if (modelCol >= 5 && ((modelCol - 5) % 2 == 0)) {
            int statusModelCol = modelCol + 1;
            int statusViewCol = table.convertColumnIndexToView(statusModelCol);
            if (statusViewCol >= 0) {
              String st = String.valueOf(table.getValueAt(row, statusViewCol));
              if (!statusMatches(st, allowBypassed, allowUnknown, allowEnforced)) {
                setText("");
                setForeground(baseFg);
                setBackground(baseBg);
              }
            }
          }
        }
      }

      return this;
    }

    private static boolean isDark(Color c) {
      if (c == null) return false;
      double lum = (0.2126 * c.getRed() + 0.7152 * c.getGreen() + 0.0722 * c.getBlue()) / 255.0;
      return lum < 0.5;
    }

    private static Color blend(Color base, Color tint, float alpha) {
      if (base == null) return tint;
      if (tint == null) return base;
      float a = Math.max(0f, Math.min(1f, alpha));
      int r = (int) (base.getRed() * (1f - a) + tint.getRed() * a);
      int g = (int) (base.getGreen() * (1f - a) + tint.getGreen() * a);
      int b = (int) (base.getBlue() * (1f - a) + tint.getBlue() * a);
      return new Color(clamp(r), clamp(g), clamp(b));
    }

    private static int clamp(int v) {
      if (v < 0) return 0;
      return Math.min(255, v);
    }
  }
}
