package autorize.ui;

import autorize.core.AutorizeState;
import burp.api.montoya.MontoyaApi;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JSplitPane;
import javax.swing.JToggleButton;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

public final class AutorizeTab {
  private final AutorizeState state;

  private final ResultsPanel resultsPanel;
  private final UsersPanel usersPanel;
  private final InterceptionFiltersPanel interceptionFiltersPanel;
  private final EnforcementRulesPanel unauthEnforcementPanel;
  private final SaveRestorePanel saveRestorePanel;

  public AutorizeTab(MontoyaApi api, AutorizeState state) {
    this.state = state;
    this.resultsPanel = new ResultsPanel(api, state);
    this.usersPanel = new UsersPanel(state);
    this.interceptionFiltersPanel = new InterceptionFiltersPanel(state);
    this.unauthEnforcementPanel = new EnforcementRulesPanel(
        state.unauthEnforcementRules(),
        state::unauthEnforcementAndOr,
        state::setUnauthEnforcementAndOr,
        state::notifyConfigChanged
    );
    this.saveRestorePanel = new SaveRestorePanel(state);
  }

  public ResultsPanel resultsPanel() {
    return resultsPanel;
  }

  public JPanel build() {
    JPanel root = new JPanel(new BorderLayout());

    boolean enabledInitial = state.enabled();
    JToggleButton enabled = new JToggleButton(enabledInitial ? "Autorize is on" : "Autorize is off");
    enabled.setSelected(enabledInitial);
    enabled.addActionListener(e -> {
      boolean on = enabled.isSelected();
      enabled.setText(on ? "Autorize is on" : "Autorize is off");
      state.setEnabled(on);
    });

    JCheckBox ignore304 = new JCheckBox("Ignore 304/204");
    ignore304.setSelected(state.ignore304());
    ignore304.addActionListener(e -> state.setIgnore304(ignore304.isSelected()));

    JCheckBox prevent304 = new JCheckBox("Prevent 304 (strip If-None-Match/If-Modified-Since)");
    prevent304.setSelected(state.prevent304());
    prevent304.addActionListener(e -> state.setPrevent304(prevent304.isSelected()));

    JCheckBox interceptRepeater = new JCheckBox("Intercept from Repeater");
    interceptRepeater.setSelected(state.interceptRepeater());
    interceptRepeater.addActionListener(e -> state.setInterceptRepeater(interceptRepeater.isSelected()));

    JCheckBox checkUnauth = new JCheckBox("Check unauthenticated");
    checkUnauth.setSelected(state.checkUnauthenticated());
    checkUnauth.addActionListener(e -> state.setCheckUnauthenticated(checkUnauth.isSelected()));

    JCheckBox autoScroll = new JCheckBox("Auto scroll");
    autoScroll.setSelected(state.autoScroll());
    autoScroll.addActionListener(e -> state.setAutoScroll(autoScroll.isSelected()));

    JCheckBox replaceQuery = new JCheckBox("Replace query param");
    replaceQuery.setSelected(state.replaceQueryParam());
    replaceQuery.addActionListener(e -> state.setReplaceQueryParam(replaceQuery.isSelected()));

    JTextField replaceQueryText = new JTextField(state.replaceQueryParamText(), 18);
    replaceQueryText.addActionListener(e -> state.setReplaceQueryParamText(replaceQueryText.getText()));
    replaceQueryText.getDocument().addDocumentListener(new SimpleDocumentListener(() ->
        state.setReplaceQueryParamText(replaceQueryText.getText())
    ));

    JButton clear = new JButton("Clear table");
    clear.addActionListener(e -> state.clearLog());

    // Control pane (matches legacy: keep toggles off the very top-level and near configuration).
    JPanel controls = new JPanel(new GridBagLayout());
    controls.setBorder(BorderFactory.createTitledBorder("Controls"));
    GridBagConstraints c = new GridBagConstraints();
    c.gridx = 0;
    c.gridy = 0;
    c.weightx = 1.0;
    c.fill = GridBagConstraints.HORIZONTAL;
    c.insets = new Insets(4, 6, 4, 6);

    controls.add(enabled, c);
    c.gridy++;
    controls.add(interceptRepeater, c);
    c.gridy++;
    controls.add(checkUnauth, c);
    c.gridy++;
    controls.add(ignore304, c);
    c.gridy++;
    controls.add(prevent304, c);
    c.gridy++;
    controls.add(autoScroll, c);

    c.gridy++;
    JPanel qp = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
    qp.add(replaceQuery);
    qp.add(new JLabel(" "));
    qp.add(replaceQueryText);
    controls.add(qp, c);

    c.gridy++;
    controls.add(clear, c);

    JTabbedPane configTabs = new JTabbedPane();
    configTabs.addTab("Users", usersPanel.ui());
    configTabs.addTab("Interception Filters", interceptionFiltersPanel.ui());
    configTabs.addTab("Unauth Detector", unauthEnforcementPanel.ui());
    configTabs.addTab("Save/Restore", saveRestorePanel.ui());

    JPanel left = new JPanel(new BorderLayout());
    left.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
    left.add(controls, BorderLayout.NORTH);
    left.add(configTabs, BorderLayout.CENTER);

    JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
    split.setResizeWeight(0.35);
    split.setLeftComponent(left);
    split.setRightComponent(resultsPanel.ui());

    // Encourage sensible minimum sizing, especially when users have many profiles/columns.
    left.setMinimumSize(new java.awt.Dimension(380, 200));
    ((JComponent) resultsPanel.ui()).setMinimumSize(new java.awt.Dimension(600, 200));

    root.add(split, BorderLayout.CENTER);

    state.addListener(new AutorizeState.Listener() {
      @Override
      public void onProfilesChanged() {
        resultsPanel.refreshProfiles();
      }

      @Override
      public void onLogChanged() {
        resultsPanel.refreshLog();
      }

      @Override
      public void onConfigChanged() {
        interceptionFiltersPanel.refresh();
        unauthEnforcementPanel.refresh();
      }
    });

    resultsPanel.refreshProfiles();
    resultsPanel.refreshLog();

    return root;
  }
}
