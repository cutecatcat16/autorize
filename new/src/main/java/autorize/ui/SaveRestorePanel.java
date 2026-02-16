package autorize.ui;

import autorize.config.AutorizeConfigCodec;
import autorize.core.AutorizeState;
import autorize.export.ResultsExport;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public final class SaveRestorePanel {
  private final AutorizeState state;

  private final JPanel root = new JPanel(new BorderLayout());
  private final JTextArea preview = new JTextArea(12, 80);

  public SaveRestorePanel(AutorizeState state) {
    this.state = state;

    root.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

    JPanel configRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
    JButton exportBtn = new JButton("Export JSON...");
    JButton importBtn = new JButton("Import JSON...");
    JButton refreshBtn = new JButton("Refresh Preview");

    configRow.add(exportBtn);
    configRow.add(importBtn);
    configRow.add(refreshBtn);

    JPanel configBox = new JPanel(new BorderLayout());
    configBox.setBorder(BorderFactory.createTitledBorder("Config"));
    configBox.add(configRow, BorderLayout.CENTER);

    JPanel resultsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
    JButton exportCsvBtn = new JButton("Export Results CSV...");
    JButton exportResultsJsonBtn = new JButton("Export Results JSON...");
    JButton exportResultsHtmlBtn = new JButton("Export Results HTML...");

    JComboBox<String> exportFilter = new JComboBox<>(new String[] {
        ResultsExport.FILTER_ALL,
        ResultsExport.FILTER_AS_TABLE,
        "Bypassed!",
        "Is enforced???",
        "Enforced!"
    });

    resultsRow.add(exportCsvBtn);
    resultsRow.add(exportResultsJsonBtn);
    resultsRow.add(exportResultsHtmlBtn);
    resultsRow.add(new JLabel("Filter:"));
    resultsRow.add(exportFilter);

    JPanel resultsBox = new JPanel(new BorderLayout());
    resultsBox.setBorder(BorderFactory.createTitledBorder("Results"));
    resultsBox.add(resultsRow, BorderLayout.CENTER);

    JPanel actions = new JPanel(new GridBagLayout());
    GridBagConstraints c = new GridBagConstraints();
    c.gridx = 0;
    c.gridy = 0;
    c.weightx = 1.0;
    c.fill = GridBagConstraints.HORIZONTAL;
    c.insets = new Insets(0, 0, 8, 0);
    actions.add(configBox, c);
    c.gridy++;
    c.insets = new Insets(0, 0, 0, 0);
    actions.add(resultsBox, c);

    preview.setEditable(false);
    preview.setLineWrap(true);
    preview.setWrapStyleWord(true);
    preview.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

    JPanel previewPanel = new JPanel(new BorderLayout());
    previewPanel.setBorder(BorderFactory.createTitledBorder("JSON Preview"));
    previewPanel.add(new JScrollPane(preview), BorderLayout.CENTER);

    JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    split.setResizeWeight(0.35);
    split.setTopComponent(actions);
    split.setBottomComponent(previewPanel);

    root.add(split, BorderLayout.CENTER);

    exportBtn.addActionListener(e -> exportJson());
    importBtn.addActionListener(e -> importJson());
    refreshBtn.addActionListener(e -> refreshPreview());
    exportCsvBtn.addActionListener(e -> exportResultsCsv());
    exportResultsJsonBtn.addActionListener(e -> exportResultsJson());
    exportResultsHtmlBtn.addActionListener(e -> exportResultsHtml((String) exportFilter.getSelectedItem()));

    refreshPreview();
  }

  public JPanel ui() {
    return root;
  }

  private void refreshPreview() {
    try {
      preview.setText(AutorizeConfigCodec.toJson(state));
      preview.setCaretPosition(0);
    } catch (IOException ex) {
      preview.setText("Failed to generate JSON preview: " + ex);
    }
  }

  private void exportJson() {
    JFileChooser fc = chooser("Export config", true);
    int r = fc.showSaveDialog(root);
    if (r != JFileChooser.APPROVE_OPTION) return;

    var file = fc.getSelectedFile().toPath();
    if (!file.toString().toLowerCase().endsWith(".json")) {
      file = file.resolveSibling(file.getFileName().toString() + ".json");
    }

    try {
      String json = AutorizeConfigCodec.toJson(state);
      Files.writeString(file, json, StandardCharsets.UTF_8);
      JOptionPane.showMessageDialog(root, "Exported to:\n" + file, "Autorize", JOptionPane.INFORMATION_MESSAGE);
    } catch (Exception ex) {
      JOptionPane.showMessageDialog(root, "Export failed:\n" + ex, "Autorize", JOptionPane.ERROR_MESSAGE);
    }
  }

  private void importJson() {
    JFileChooser fc = chooser("Import config", false);
    int r = fc.showOpenDialog(root);
    if (r != JFileChooser.APPROVE_OPTION) return;

    var file = fc.getSelectedFile().toPath();

    try {
      String json = Files.readString(file, StandardCharsets.UTF_8);
      AutorizeConfigCodec.applyJsonToState(json, state);
      refreshPreview();
      JOptionPane.showMessageDialog(root, "Imported from:\n" + file, "Autorize", JOptionPane.INFORMATION_MESSAGE);
    } catch (Exception ex) {
      JOptionPane.showMessageDialog(root, "Import failed:\n" + ex, "Autorize", JOptionPane.ERROR_MESSAGE);
    }
  }

  private static JFileChooser chooser(String title, boolean save) {
    JFileChooser fc = new JFileChooser();
    fc.setDialogTitle(title);
    fc.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
    return fc;
  }

  private void exportResultsCsv() {
    JFileChooser fc = new JFileChooser();
    fc.setDialogTitle("Export results (CSV)");
    fc.setFileFilter(new FileNameExtensionFilter("CSV files", "csv"));
    int r = fc.showSaveDialog(root);
    if (r != JFileChooser.APPROVE_OPTION) return;

    var file = fc.getSelectedFile().toPath();
    if (!file.toString().toLowerCase().endsWith(".csv")) {
      file = file.resolveSibling(file.getFileName().toString() + ".csv");
    }

    try {
      String csv = ResultsExport.toCsv(state);
      Files.writeString(file, csv, StandardCharsets.UTF_8);
      JOptionPane.showMessageDialog(root, "Exported results to:\n" + file, "Autorize", JOptionPane.INFORMATION_MESSAGE);
    } catch (Exception ex) {
      JOptionPane.showMessageDialog(root, "Export failed:\n" + ex, "Autorize", JOptionPane.ERROR_MESSAGE);
    }
  }

  private void exportResultsJson() {
    JFileChooser fc = new JFileChooser();
    fc.setDialogTitle("Export results (JSON)");
    fc.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
    int r = fc.showSaveDialog(root);
    if (r != JFileChooser.APPROVE_OPTION) return;

    var file = fc.getSelectedFile().toPath();
    if (!file.toString().toLowerCase().endsWith(".json")) {
      file = file.resolveSibling(file.getFileName().toString() + ".json");
    }

    try {
      String json = ResultsExport.toJson(state);
      Files.writeString(file, json, StandardCharsets.UTF_8);
      JOptionPane.showMessageDialog(root, "Exported results to:\n" + file, "Autorize", JOptionPane.INFORMATION_MESSAGE);
    } catch (Exception ex) {
      JOptionPane.showMessageDialog(root, "Export failed:\n" + ex, "Autorize", JOptionPane.ERROR_MESSAGE);
    }
  }

  private void exportResultsHtml(String filterMode) {
    JFileChooser fc = new JFileChooser();
    fc.setDialogTitle("Export results (HTML)");
    fc.setFileFilter(new FileNameExtensionFilter("HTML files", "html"));
    int r = fc.showSaveDialog(root);
    if (r != JFileChooser.APPROVE_OPTION) return;

    var file = fc.getSelectedFile().toPath();
    if (!file.toString().toLowerCase().endsWith(".html")) {
      file = file.resolveSibling(file.getFileName().toString() + ".html");
    }

    try {
      String html = ResultsExport.toHtml(state, filterMode);
      Files.writeString(file, html, StandardCharsets.UTF_8);
      JOptionPane.showMessageDialog(root, "Exported results to:\n" + file, "Autorize", JOptionPane.INFORMATION_MESSAGE);
    } catch (Exception ex) {
      JOptionPane.showMessageDialog(root, "Export failed:\n" + ex, "Autorize", JOptionPane.ERROR_MESSAGE);
    }
  }
}
