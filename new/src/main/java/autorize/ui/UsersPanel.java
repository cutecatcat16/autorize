package autorize.ui;

import autorize.core.AutorizeState;
import autorize.model.UserProfile;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.UUID;

public final class UsersPanel {
  private final AutorizeState state;

  private final JPanel root = new JPanel(new BorderLayout());
  private final JTabbedPane tabs = new JTabbedPane();
  private final JPanel plusPanel = new JPanel();

  private static final String KEY_PROFILE_ID_PREFIX = "autorize.profileId:";
  private volatile boolean rebuilding = false;
  private volatile int lastNonPlusIndex = 0;

  public UsersPanel(AutorizeState state) {
    this.state = state;

    root.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
    root.add(tabs, BorderLayout.CENTER);

    state.addListener(new AutorizeState.Listener() {
      @Override
      public void onProfilesChanged() {
        rebuildTabs();
      }

      @Override
      public void onLogChanged() {
        // no-op
      }

      @Override
      public void onConfigChanged() {
        // no-op
      }
    });

    // Click "+" tab to add a new user; double click user tab to rename.
    tabs.addMouseListener(new MouseAdapter() {
      @Override
      public void mousePressed(MouseEvent e) {
        if (e.getButton() != MouseEvent.BUTTON1) return;
        int idx = tabs.indexAtLocation(e.getX(), e.getY());
        if (idx < 0) return;
        if (isPlusTabIndex(idx)) {
          if (!rebuilding) {
            addUserFromPlusTab();
          }
          return;
        }
      }

      @Override
      public void mouseClicked(MouseEvent e) {
        if (e.getButton() != MouseEvent.BUTTON1) return;
        if (e.getClickCount() != 2) return;
        int idx = tabs.indexAtLocation(e.getX(), e.getY());
        if (idx < 0) return;
        if (isPlusTabIndex(idx)) return;
        UUID id = profileIdAtIndex(idx);
        if (id == null) return;
        renameUserViaDialog(id);
      }
    });

    rebuildTabs();
  }

  public JPanel ui() {
    return root;
  }

  private UUID selectedProfileId() {
    int idx = tabs.getSelectedIndex();
    if (idx < 0) return null;
    return profileIdAtIndex(idx);
  }

  private boolean isPlusTabIndex(int idx) {
    return idx >= 0 && idx == tabs.getTabCount() - 1;
  }

  private UUID profileIdAtIndex(int idx) {
    if (idx < 0) return null;
    if (isPlusTabIndex(idx)) return null;
    Object o = tabs.getClientProperty(KEY_PROFILE_ID_PREFIX + idx);
    return (o instanceof UUID) ? (UUID) o : null;
  }

  private void rebuildTabs() {
    rebuilding = true;
    try {
      UUID selectedId = selectedProfileId();
      tabs.removeAll();

      List<UserProfile> profiles = state.profilesSnapshot();
      for (int i = 0; i < profiles.size(); i++) {
        UserProfile p = profiles.get(i);
        JPanel content = profilePanel(p);
        tabs.addTab(p.name(), content);
        tabs.putClientProperty(KEY_PROFILE_ID_PREFIX + i, p.id());
        tabs.setTabComponentAt(i, makeClosableTabComponent(p.id(), p.name()));
      }

      // "+" tab at the end for adding users.
      tabs.addTab("+", plusPanel);
      tabs.setTabComponentAt(tabs.getTabCount() - 1, makePlusTabComponent());

      // Restore selection by profile id.
      if (selectedId != null) {
        for (int i = 0; i < profiles.size(); i++) {
          if (profiles.get(i).id().equals(selectedId)) {
            tabs.setSelectedIndex(i);
            lastNonPlusIndex = i;
            return;
          }
        }
      }
      if (!profiles.isEmpty()) {
        tabs.setSelectedIndex(0);
        lastNonPlusIndex = 0;
      }
    } finally {
      rebuilding = false;
    }
  }

  private void addUserFromPlusTab() {
    // If the plus tab is selected, add exactly one user, then switch selection to the new tab.
    int n = state.profilesSnapshot().size() + 1;
    state.addProfile(UserProfile.create("User " + n));

    // Select the newly added user tab (last profile tab, before "+").
    SwingUtilities.invokeLater(() -> {
      int idx = Math.max(0, tabs.getTabCount() - 2);
      if (idx < tabs.getTabCount()) {
        tabs.setSelectedIndex(idx);
        lastNonPlusIndex = idx;
      }
    });
  }

  private void renameUserViaDialog(UUID id) {
    UserProfile p = state.profileById(id);
    if (p == null) return;
    String newName = JOptionPane.showInputDialog(root, "Enter new name:", p.name());
    if (newName == null) return;
    newName = newName.trim();
    if (newName.isEmpty()) return;
    state.renameProfile(id, newName);
  }

  private JComponent makePlusTabComponent() {
    JLabel l = new JLabel("+");
    JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
    p.setOpaque(false);
    p.add(l);
    return p;
  }

  private JComponent makeClosableTabComponent(UUID profileId, String title) {
    JLabel l = new JLabel(title);
    JButton close = new JButton("x");
    close.setMargin(new Insets(0, 4, 0, 4));
    close.setBorderPainted(false);
    close.setContentAreaFilled(false);
    close.setFocusable(false);
    close.setToolTipText("Remove user");
    close.addActionListener(e -> state.removeProfile(profileId));

    JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
    p.setOpaque(false);
    p.add(l);
    p.add(close);
    return p;
  }

  private JPanel profilePanel(UserProfile profile) {
    JPanel p = new JPanel(new BorderLayout());
    p.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

    JTabbedPane subtabs = new JTabbedPane();

    // Match/Replace tab
    MatchReplacePanel mr = new MatchReplacePanel(profile.matchReplaceRules(), state::notifyConfigChanged);
    subtabs.addTab("Match/Replace", mr.ui());

    // Enforcement Detector tab
    EnforcementRulesPanel ed = new EnforcementRulesPanel(
        profile.enforcementRules(),
        profile::enforcementAndOr,
        profile::setEnforcementAndOr,
        state::notifyConfigChanged
    );
    subtabs.addTab("Enforcement Detector", ed.ui());

    p.add(subtabs, BorderLayout.CENTER);
    return p;
  }
}
