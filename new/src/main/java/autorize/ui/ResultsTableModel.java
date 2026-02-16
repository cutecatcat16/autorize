package autorize.ui;

import autorize.core.AutorizeState;
import autorize.model.LogEntry;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class ResultsTableModel extends AbstractTableModel {
  private final AutorizeState state;

  public ResultsTableModel(AutorizeState state) {
    this.state = state;
  }

  @Override
  public Class<?> getColumnClass(int columnIndex) {
    // Ensure TableRowSorter does numeric sorting for counters/lengths.
    if (columnIndex == 0) return Integer.class; // #
    if (columnIndex == 2) return Integer.class; // orig len
    if (columnIndex == 3) return Integer.class; // unauth len
    if (columnIndex >= 5) {
      int idx = columnIndex - 5;
      int colType = idx % 2; // 0 len, 1 status
      if (colType == 0) return Integer.class;
      return String.class;
    }
    return String.class;
  }

  @Override
  public int getRowCount() {
    return state.logSnapshot().size();
  }

  @Override
  public int getColumnCount() {
    // #, url, origLen, unauthLen, unauthStatus, then (len,status) per profile
    return 5 + (state.profileNamesSnapshot().size() * 2);
  }

  @Override
  public String getColumnName(int column) {
    if (column == 0) return "#";
    if (column == 1) return "URL";
    if (column == 2) return "Orig. Len";
    if (column == 3) return "Unauth. Len";
    if (column == 4) return "Unauth. Status";

    int idx = column - 5;
    int userIdx = idx / 2;
    int colType = idx % 2; // 0 len, 1 status

    List<Map.Entry<UUID, String>> profiles = new ArrayList<>(state.profileNamesSnapshot().entrySet());
    if (userIdx >= 0 && userIdx < profiles.size()) {
      String name = profiles.get(userIdx).getValue();
      return colType == 0 ? (name + " Len") : (name + " Status");
    }
    return "";
  }

  @Override
  public Object getValueAt(int rowIndex, int columnIndex) {
    List<LogEntry> log = state.logSnapshot();
    if (rowIndex < 0 || rowIndex >= log.size()) return "";
    LogEntry e = log.get(rowIndex);

    if (columnIndex == 0) return e.number();
    if (columnIndex == 1) return e.url();
    if (columnIndex == 2) {
      var res = e.original() == null ? null : e.original().response();
      return res == null ? 0 : res.body().length();
    }
    if (columnIndex == 3) {
      var rr = e.unauthenticated();
      if (rr == null || !rr.hasResponse() || rr.response() == null) return 0;
      return rr.response().body().length();
    }
    if (columnIndex == 4) return e.unauthVerdict();

    int idx = columnIndex - 5;
    int userIdx = idx / 2;
    int colType = idx % 2;

    List<UUID> ids = new ArrayList<>(state.profileNamesSnapshot().keySet());
    if (userIdx >= 0 && userIdx < ids.size()) {
      UUID id = ids.get(userIdx);
      if (colType == 0) {
        var rr = e.perProfile().get(id);
        if (rr == null || !rr.hasResponse() || rr.response() == null) return 0;
        return rr.response().body().length();
      }
      return e.perProfileVerdict().getOrDefault(id, "");
    }
    return "";
  }
}
