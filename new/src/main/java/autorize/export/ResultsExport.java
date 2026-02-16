package autorize.export;

import autorize.core.AutorizeState;
import autorize.model.LogEntry;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class ResultsExport {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private ResultsExport() {}

  public static final String FILTER_ALL = "All Statuses";
  public static final String FILTER_AS_TABLE = "As table filter";

  public static String toCsv(AutorizeState state) {
    StringBuilder sb = new StringBuilder();

    Map<UUID, String> profiles = state.profileNamesSnapshot();
    List<UUID> profileIds = new ArrayList<>(profiles.keySet());

    // Header
    sb.append("ID,Method,URL,OrigLen,UnauthLen,UnauthStatus");
    for (UUID id : profileIds) {
      String name = profiles.get(id);
      sb.append(',').append(csv(name + " Len"));
      sb.append(',').append(csv(name + " Status"));
    }
    sb.append("\n");

    for (LogEntry e : state.logSnapshot()) {
      sb.append(e.number()).append(',');
      sb.append(csv(e.method())).append(',');
      sb.append(csv(e.url())).append(',');
      sb.append(origLen(e)).append(',');
      sb.append(unauthLen(e)).append(',');
      sb.append(csv(e.unauthVerdict()));

      for (UUID id : profileIds) {
        sb.append(',').append(profileLen(e, id));
        sb.append(',').append(csv(e.perProfileVerdict().getOrDefault(id, "")));
      }
      sb.append("\n");
    }

    return sb.toString();
  }

  public static String toJson(AutorizeState state) throws IOException {
    Map<UUID, String> profiles = state.profileNamesSnapshot();
    List<UUID> profileIds = new ArrayList<>(profiles.keySet());

    List<Map<String, Object>> rows = new ArrayList<>();
    for (LogEntry e : state.logSnapshot()) {
      Map<String, Object> row = new LinkedHashMap<>();
      row.put("id", e.number());
      row.put("method", e.method());
      row.put("url", e.url());
      row.put("origLen", origLen(e));
      row.put("unauthLen", unauthLen(e));
      row.put("unauthStatus", e.unauthVerdict());

      Map<String, Object> perUser = new LinkedHashMap<>();
      for (UUID id : profileIds) {
        Map<String, Object> u = new LinkedHashMap<>();
        u.put("len", profileLen(e, id));
        u.put("status", e.perProfileVerdict().getOrDefault(id, ""));
        perUser.put(profiles.get(id), u);
      }
      row.put("profiles", perUser);
      rows.add(row);
    }

    return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(rows);
  }

  public static String toHtml(AutorizeState state, String filterMode) {
    Map<UUID, String> profiles = state.profileNamesSnapshot();
    List<UUID> profileIds = new ArrayList<>(profiles.keySet());

    String mode = filterMode == null ? FILTER_ALL : filterMode;

    StringBuilder sb = new StringBuilder();
    sb.append("<html><head><meta charset=\"utf-8\"/>");
    sb.append("<title>Autorize Report</title>");
    sb.append("<style>");
    sb.append("body{font-family:Arial,Helvetica,sans-serif;font-size:12px;}");
    sb.append("table{border-collapse:collapse;width:100%;}");
    sb.append("th,td{border:1px solid #e1eef4;padding:6px;}");
    sb.append("th{background:#006699;color:#fff;text-align:left;}");
    sb.append(".bypassed{background:#ff9999;}");
    sb.append(".unknown{background:#ffcc99;}");
    sb.append(".enforced{background:#ccff99;}");
    sb.append(".disabled{background:#d3d3d3;}");
    sb.append("</style></head><body>");
    sb.append("<h1>Autorize Report</h1>");
    sb.append("<p>Filter: ").append(escapeHtml(mode)).append("</p>");

    sb.append("<table><thead><tr>");
    sb.append("<th>ID</th><th>Method</th><th>URL</th><th>Orig Len</th><th>Unauth Len</th><th>Unauth Status</th>");
    for (UUID id : profileIds) {
      String name = profiles.get(id);
      sb.append("<th>").append(escapeHtml(name)).append(" Len</th>");
      sb.append("<th>").append(escapeHtml(name)).append(" Status</th>");
    }
    sb.append("</tr></thead><tbody>");

    for (LogEntry e : state.logSnapshot()) {
      if (!shouldIncludeRow(state, e, mode)) continue;

      sb.append("<tr>");
      sb.append("<td>").append(e.number()).append("</td>");
      sb.append("<td>").append(escapeHtml(e.method())).append("</td>");
      sb.append("<td>").append(escapeHtml(e.url())).append("</td>");
      sb.append("<td>").append(origLen(e)).append("</td>");
      sb.append("<td>").append(unauthLen(e)).append("</td>");
      sb.append("<td class=\"").append(cssClassForStatus(e.unauthVerdict())).append("\">")
          .append(escapeHtml(e.unauthVerdict())).append("</td>");

      for (UUID id : profileIds) {
        sb.append("<td>").append(profileLen(e, id)).append("</td>");
        String st = e.perProfileVerdict().getOrDefault(id, "");
        sb.append("<td class=\"").append(cssClassForStatus(st)).append("\">")
            .append(escapeHtml(st)).append("</td>");
      }
      sb.append("</tr>");
    }

    sb.append("</tbody></table>");
    sb.append("</body></html>");
    return sb.toString();
  }

  private static int origLen(LogEntry e) {
    try {
      var rr = e.original();
      if (rr == null || !rr.hasResponse() || rr.response() == null) return 0;
      return rr.response().body().length();
    } catch (Exception ex) {
      return 0;
    }
  }

  private static int unauthLen(LogEntry e) {
    try {
      var rr = e.unauthenticated();
      if (rr == null || !rr.hasResponse() || rr.response() == null) return 0;
      return rr.response().body().length();
    } catch (Exception ex) {
      return 0;
    }
  }

  private static int profileLen(LogEntry e, UUID id) {
    try {
      var rr = e.perProfile().get(id);
      if (rr == null || !rr.hasResponse() || rr.response() == null) return 0;
      return rr.response().body().length();
    } catch (Exception ex) {
      return 0;
    }
  }

  private static String csv(String s) {
    if (s == null) return "";
    String v = s.replace("\"", "\"\"");
    if (v.contains(",") || v.contains("\n") || v.contains("\r")) {
      return "\"" + v + "\"";
    }
    return v;
  }

  private static boolean shouldIncludeRow(AutorizeState state, LogEntry e, String filterMode) {
    String mode = filterMode == null ? FILTER_ALL : filterMode;
    if (FILTER_ALL.equals(mode)) return true;

    if (FILTER_AS_TABLE.equals(mode)) {
      boolean allowBypassed = state.showBypassed();
      boolean allowEnforced = state.showEnforced();
      boolean allowUnknown = state.showUnknown();
      if (allowBypassed && allowEnforced && allowUnknown) return true;
      if ("Disabled".equals(e.unauthVerdict())) return true;
      if (statusMatches(e.unauthVerdict(), allowBypassed, allowUnknown, allowEnforced)) return true;
      for (String v : e.perProfileVerdict().values()) {
        if (statusMatches(v, allowBypassed, allowUnknown, allowEnforced)) return true;
      }
      return false;
    }

    if (mode.equals(e.unauthVerdict())) return true;
    for (String v : e.perProfileVerdict().values()) {
      if (mode.equals(v)) return true;
    }
    return false;
  }

  private static boolean statusMatches(String status, boolean allowBypassed, boolean allowUnknown, boolean allowEnforced) {
    if (status == null) return false;
    if (status.contains("Bypassed")) return allowBypassed;
    if (status.contains("Is enforced")) return allowUnknown;
    if (status.contains("Enforced")) return allowEnforced;
    return false;
  }

  private static String cssClassForStatus(String status) {
    if (status == null) return "";
    if ("Disabled".equals(status)) return "disabled";
    if (status.contains("Bypassed")) return "bypassed";
    if (status.contains("Is enforced")) return "unknown";
    if (status.contains("Enforced")) return "enforced";
    return "";
  }

  private static String escapeHtml(String s) {
    if (s == null) return "";
    return s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;");
  }
}
