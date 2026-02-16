package autorize.core;

import autorize.model.LogEntry;
import autorize.model.AndOr;
import autorize.model.EnforcementRule;
import autorize.model.InterceptionFilter;
import autorize.model.InterceptionFilterType;
import autorize.model.UserProfile;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public final class AutorizeState {
  public interface Listener {
    void onProfilesChanged();
    void onLogChanged();
    void onConfigChanged();
  }

  private final AtomicBoolean enabled = new AtomicBoolean(false);
  private final AtomicBoolean interceptRepeater = new AtomicBoolean(false);
  private final AtomicBoolean checkUnauthenticated = new AtomicBoolean(true);

  private final AtomicBoolean ignore304 = new AtomicBoolean(true);
  private final AtomicBoolean prevent304 = new AtomicBoolean(false);
  private final AtomicBoolean autoScroll = new AtomicBoolean(false);

  private final AtomicBoolean replaceQueryParam = new AtomicBoolean(false);
  private volatile String replaceQueryParamText = "paramName=paramValue";

  // Legacy table filter semantics (also used for exports).
  private final AtomicBoolean showBypassed = new AtomicBoolean(true);
  private final AtomicBoolean showEnforced = new AtomicBoolean(true);
  private final AtomicBoolean showUnknown = new AtomicBoolean(true);


  private final List<InterceptionFilter> interceptionFilters = new CopyOnWriteArrayList<>();
  private final List<EnforcementRule> unauthEnforcementRules = new CopyOnWriteArrayList<>();
  private volatile AndOr unauthEnforcementAndOr = AndOr.OR;

  private final AtomicInteger requestCounter = new AtomicInteger(1);

  private final List<UserProfile> profiles = new CopyOnWriteArrayList<>();
  private final List<LogEntry> log = new CopyOnWriteArrayList<>();
  private final List<Listener> listeners = new CopyOnWriteArrayList<>();

  public AutorizeState() {
    profiles.add(UserProfile.create("User 1"));

    // Default: respect Burp project scope.
    interceptionFilters.add(new InterceptionFilter(InterceptionFilterType.SCOPE_ONLY, ""));

    // Default: ignore obvious static assets (legacy does something similar).
    interceptionFilters.add(new InterceptionFilter(
        InterceptionFilterType.URL_NOT_REGEX,
        "(\\.js|\\.css|\\.png|\\.jpg|\\.svg|\\.jpeg|\\.gif|\\.woff|\\.map|\\.bmp|\\.ico)(?![a-z]+)[?]*[\\S]*$"
    ));
    interceptionFilters.add(new InterceptionFilter(InterceptionFilterType.IGNORE_OPTIONS, ""));
  }

  public void addListener(Listener l) {
    listeners.add(l);
  }

  public void notifyConfigChanged() {
    for (Listener l : listeners) {
      l.onConfigChanged();
    }
  }

  public boolean enabled() {
    return enabled.get();
  }

  public void setEnabled(boolean value) {
    enabled.set(value);
    notifyConfigChanged();
  }

  public boolean interceptRepeater() {
    return interceptRepeater.get();
  }

  public void setInterceptRepeater(boolean value) {
    interceptRepeater.set(value);
    notifyConfigChanged();
  }

  public boolean checkUnauthenticated() {
    return checkUnauthenticated.get();
  }

  public void setCheckUnauthenticated(boolean value) {
    checkUnauthenticated.set(value);
    notifyConfigChanged();
  }

  public boolean ignore304() {
    return ignore304.get();
  }

  public void setIgnore304(boolean value) {
    ignore304.set(value);
    notifyConfigChanged();
  }

  public boolean prevent304() {
    return prevent304.get();
  }

  public void setPrevent304(boolean value) {
    prevent304.set(value);
    notifyConfigChanged();
  }

  public boolean autoScroll() {
    return autoScroll.get();
  }

  public void setAutoScroll(boolean value) {
    autoScroll.set(value);
    notifyConfigChanged();
  }

  public boolean replaceQueryParam() {
    return replaceQueryParam.get();
  }

  public void setReplaceQueryParam(boolean value) {
    replaceQueryParam.set(value);
    notifyConfigChanged();
  }

  public String replaceQueryParamText() {
    return replaceQueryParamText;
  }

  public void setReplaceQueryParamText(String text) {
    replaceQueryParamText = text == null ? "" : text;
    notifyConfigChanged();
  }

  public boolean showBypassed() {
    return showBypassed.get();
  }

  public void setShowBypassed(boolean value) {
    showBypassed.set(value);
    notifyConfigChanged();
  }

  public boolean showEnforced() {
    return showEnforced.get();
  }

  public void setShowEnforced(boolean value) {
    showEnforced.set(value);
    notifyConfigChanged();
  }

  public boolean showUnknown() {
    return showUnknown.get();
  }

  public void setShowUnknown(boolean value) {
    showUnknown.set(value);
    notifyConfigChanged();
  }


  public int nextRequestNumber() {
    return requestCounter.getAndIncrement();
  }

  public List<UserProfile> profilesSnapshot() {
    return new ArrayList<>(profiles);
  }

  public UserProfile profileById(UUID id) {
    for (UserProfile p : profiles) {
      if (p.id().equals(id)) {
        return p;
      }
    }
    return null;
  }

  public void addProfile(UserProfile profile) {
    profiles.add(profile);
    for (Listener l : listeners) {
      l.onProfilesChanged();
    }
  }

  public void removeProfile(UUID id) {
    if (profiles.size() <= 1) {
      return;
    }
    profiles.removeIf(p -> p.id().equals(id));
    for (Listener l : listeners) {
      l.onProfilesChanged();
    }
  }

  public void renameProfile(UUID id, String newName) {
    UserProfile p = profileById(id);
    if (p == null) {
      return;
    }
    p.setName(newName);
    for (Listener l : listeners) {
      l.onProfilesChanged();
    }
  }

  public void duplicateProfile(UUID id) {
    UserProfile src = profileById(id);
    if (src == null) {
      return;
    }
    UserProfile dup = src.deepCopyWithName(src.name() + " Copy");
    profiles.add(dup);
    for (Listener l : listeners) {
      l.onProfilesChanged();
    }
  }

  public void updateProfileHeaders(UUID id, String headersText) {
    UserProfile p = profileById(id);
    if (p == null) {
      return;
    }
    p.setHeadersText(headersText);
    notifyConfigChanged();
  }

  public List<InterceptionFilter> interceptionFilters() {
    return interceptionFilters;
  }

  public void addInterceptionFilter(InterceptionFilter filter) {
    interceptionFilters.add(filter);
    notifyConfigChanged();
  }

  public void removeInterceptionFilter(int index) {
    if (index < 0 || index >= interceptionFilters.size()) return;
    interceptionFilters.remove(index);
    notifyConfigChanged();
  }

  public void updateInterceptionFilter(int index, InterceptionFilter filter) {
    if (index < 0 || index >= interceptionFilters.size()) return;
    interceptionFilters.set(index, filter);
    notifyConfigChanged();
  }

  public void moveInterceptionFilter(int fromIndex, int toIndex) {
    if (fromIndex < 0 || fromIndex >= interceptionFilters.size()) return;
    if (toIndex < 0 || toIndex >= interceptionFilters.size()) return;
    if (fromIndex == toIndex) return;
    InterceptionFilter f = interceptionFilters.remove(fromIndex);
    interceptionFilters.add(toIndex, f);
    notifyConfigChanged();
  }

  public List<EnforcementRule> unauthEnforcementRules() {
    return unauthEnforcementRules;
  }

  public AndOr unauthEnforcementAndOr() {
    return unauthEnforcementAndOr;
  }

  public void setUnauthEnforcementAndOr(AndOr mode) {
    this.unauthEnforcementAndOr = mode == null ? AndOr.OR : mode;
    notifyConfigChanged();
  }

  public void addUnauthEnforcementRule(EnforcementRule rule) {
    unauthEnforcementRules.add(rule);
    notifyConfigChanged();
  }

  public void removeUnauthEnforcementRule(int index) {
    if (index < 0 || index >= unauthEnforcementRules.size()) return;
    unauthEnforcementRules.remove(index);
    notifyConfigChanged();
  }

  public void updateUnauthEnforcementRule(int index, EnforcementRule rule) {
    if (index < 0 || index >= unauthEnforcementRules.size()) return;
    unauthEnforcementRules.set(index, rule);
    notifyConfigChanged();
  }

  public void replaceAllProfiles(List<UserProfile> newProfiles) {
    profiles.clear();
    if (newProfiles != null && !newProfiles.isEmpty()) {
      profiles.addAll(newProfiles);
    } else {
      profiles.add(UserProfile.create("User 1"));
    }
    for (Listener l : listeners) {
      l.onProfilesChanged();
    }
    notifyConfigChanged();
  }

  public void replaceInterceptionFilters(List<InterceptionFilter> filters) {
    interceptionFilters.clear();
    if (filters != null) {
      interceptionFilters.addAll(filters);
    }
    notifyConfigChanged();
  }

  public void replaceUnauthEnforcementRules(List<EnforcementRule> rules, AndOr mode) {
    unauthEnforcementRules.clear();
    if (rules != null) {
      unauthEnforcementRules.addAll(rules);
    }
    unauthEnforcementAndOr = mode == null ? AndOr.OR : mode;
    notifyConfigChanged();
  }

  public List<LogEntry> logSnapshot() {
    return new ArrayList<>(log);
  }

  public void clearLog() {
    log.clear();
    for (Listener l : listeners) {
      l.onLogChanged();
    }
  }

  public void addLogEntry(LogEntry entry) {
    log.add(entry);
    for (Listener l : listeners) {
      l.onLogChanged();
    }
  }

  public void removeLogRows(List<Integer> modelRows) {
    if (modelRows == null || modelRows.isEmpty()) return;
    // Remove in descending order so indexes remain valid.
    var rows = new ArrayList<>(modelRows);
    rows.sort((a, b) -> Integer.compare(b, a));
    for (Integer idx : rows) {
      if (idx == null) continue;
      int i = idx;
      if (i >= 0 && i < log.size()) {
        log.remove(i);
      }
    }
    for (Listener l : listeners) {
      l.onLogChanged();
    }
  }

  public Map<UUID, String> profileNamesSnapshot() {
    Map<UUID, String> m = new LinkedHashMap<>();
    for (UserProfile p : profiles) {
      m.put(p.id(), p.name());
    }
    return Collections.unmodifiableMap(m);
  }
}
