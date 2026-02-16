package autorize.core;

import autorize.model.AndOr;
import autorize.model.EnforcementRule;
import autorize.model.EnforcementRuleType;
import autorize.model.InterceptionFilter;
import autorize.model.InterceptionFilterType;
import autorize.model.MatchReplaceRule;
import autorize.model.MatchReplaceType;
import autorize.model.UserProfile;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.PersistedList;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Stores configuration in Montoya persisted extension data.
 *
 * We intentionally do not persist the "enabled" state for safety: extension always starts disabled.
 */
public final class AutorizePersistence {
  private static final String KEY_VERSION = "autorize.version";
  private static final int VERSION = 1;

  private static final String KEY_INTERCEPT_REPEATER = "autorize.interceptRepeater";
  private static final String KEY_CHECK_UNAUTH = "autorize.checkUnauth";
  private static final String KEY_IGNORE_304 = "autorize.ignore304";
  private static final String KEY_PREVENT_304 = "autorize.prevent304";
  private static final String KEY_AUTOSCROLL = "autorize.autoScroll";
  private static final String KEY_REPLACE_QUERY = "autorize.replaceQuery";
  private static final String KEY_REPLACE_QUERY_TEXT = "autorize.replaceQueryText";
  private static final String KEY_SHOW_BYPASSED = "autorize.showBypassed";
  private static final String KEY_SHOW_ENFORCED = "autorize.showEnforced";
  private static final String KEY_SHOW_UNKNOWN = "autorize.showUnknown";

  private static final String KEY_INTERCEPTION_FILTERS = "autorize.interceptionFilters";
  private static final String KEY_UNAUTH_MODE = "autorize.unauth.mode";
  private static final String KEY_UNAUTH_RULES = "autorize.unauth.rules";

  private static final String KEY_PROFILE_IDS = "autorize.profiles.ids";
  private static final String KEY_PROFILE_PREFIX = "autorize.profile.";

  public void save(PersistedObject root, AutorizeState state) {
    if (root == null || state == null) return;

    root.setInteger(KEY_VERSION, VERSION);
    root.setBoolean(KEY_INTERCEPT_REPEATER, state.interceptRepeater());
    root.setBoolean(KEY_CHECK_UNAUTH, state.checkUnauthenticated());
    root.setBoolean(KEY_IGNORE_304, state.ignore304());
    root.setBoolean(KEY_PREVENT_304, state.prevent304());
    root.setBoolean(KEY_AUTOSCROLL, state.autoScroll());
    root.setBoolean(KEY_REPLACE_QUERY, state.replaceQueryParam());
    root.setString(KEY_REPLACE_QUERY_TEXT, state.replaceQueryParamText());
    root.setBoolean(KEY_SHOW_BYPASSED, state.showBypassed());
    root.setBoolean(KEY_SHOW_ENFORCED, state.showEnforced());
    root.setBoolean(KEY_SHOW_UNKNOWN, state.showUnknown());

    // Interception filters
    var filterStrings = new ArrayList<String>();
    for (InterceptionFilter f : state.interceptionFilters()) {
      filterStrings.add(encodeInterceptionFilter(f));
    }
    root.setStringList(KEY_INTERCEPTION_FILTERS, persistedStringList(filterStrings));

    // Unauth enforcement
    root.setString(KEY_UNAUTH_MODE, state.unauthEnforcementAndOr().name());
    var unauthRuleStrings = new ArrayList<String>();
    for (EnforcementRule r : state.unauthEnforcementRules()) {
      unauthRuleStrings.add(encodeEnforcementRule(r));
    }
    root.setStringList(KEY_UNAUTH_RULES, persistedStringList(unauthRuleStrings));

    // Profiles
    var ids = new ArrayList<String>();
    for (UserProfile p : state.profilesSnapshot()) {
      String id = p.id().toString();
      ids.add(id);

      PersistedObject po = root.getChildObject(KEY_PROFILE_PREFIX + id);
      if (po == null) {
        po = PersistedObject.persistedObject();
        root.setChildObject(KEY_PROFILE_PREFIX + id, po);
      }

      po.setString("name", p.name());
      po.setString("headers", p.headersText());
      po.setString("mode", p.enforcementAndOr().name());

      var mrStrings = new ArrayList<String>();
      for (MatchReplaceRule mr : p.matchReplaceRules()) {
        mrStrings.add(encodeMatchReplaceRule(mr));
      }
      po.setStringList("mr", persistedStringList(mrStrings));

      var edStrings = new ArrayList<String>();
      for (EnforcementRule ed : p.enforcementRules()) {
        edStrings.add(encodeEnforcementRule(ed));
      }
      po.setStringList("ed", persistedStringList(edStrings));
    }

    root.setStringList(KEY_PROFILE_IDS, persistedStringList(ids));
  }

  public void load(PersistedObject root, AutorizeState state) {
    if (root == null || state == null) return;

    // Booleans default false/true, if missing keep defaults.
    Boolean interceptRepeater = root.getBoolean(KEY_INTERCEPT_REPEATER);
    if (interceptRepeater != null) state.setInterceptRepeater(interceptRepeater);

    Boolean checkUnauth = root.getBoolean(KEY_CHECK_UNAUTH);
    if (checkUnauth != null) state.setCheckUnauthenticated(checkUnauth);

    Boolean ignore304 = root.getBoolean(KEY_IGNORE_304);
    if (ignore304 != null) state.setIgnore304(ignore304);

    Boolean prevent304 = root.getBoolean(KEY_PREVENT_304);
    if (prevent304 != null) state.setPrevent304(prevent304);

    Boolean autoScroll = root.getBoolean(KEY_AUTOSCROLL);
    if (autoScroll != null) state.setAutoScroll(autoScroll);

    Boolean replaceQuery = root.getBoolean(KEY_REPLACE_QUERY);
    if (replaceQuery != null) state.setReplaceQueryParam(replaceQuery);

    String replaceQueryText = root.getString(KEY_REPLACE_QUERY_TEXT);
    if (replaceQueryText != null) state.setReplaceQueryParamText(replaceQueryText);

    Boolean showBypassed = root.getBoolean(KEY_SHOW_BYPASSED);
    if (showBypassed != null) state.setShowBypassed(showBypassed);
    Boolean showEnforced = root.getBoolean(KEY_SHOW_ENFORCED);
    if (showEnforced != null) state.setShowEnforced(showEnforced);
    Boolean showUnknown = root.getBoolean(KEY_SHOW_UNKNOWN);
    if (showUnknown != null) state.setShowUnknown(showUnknown);

    // Extension always starts disabled for safety.
    state.setEnabled(false);

    // Interception filters
    List<InterceptionFilter> filters = new ArrayList<>();
    var filterList = root.getStringList(KEY_INTERCEPTION_FILTERS);
    if (filterList != null) {
      for (String s : filterList) {
        InterceptionFilter f = decodeInterceptionFilter(s);
        if (f != null) filters.add(f);
      }
    }
    if (!filters.isEmpty()) {
      state.replaceInterceptionFilters(filters);
    }

    // Unauth rules
    AndOr unauthMode = safeAndOr(root.getString(KEY_UNAUTH_MODE), state.unauthEnforcementAndOr());
    List<EnforcementRule> unauthRules = new ArrayList<>();
    var unauthList = root.getStringList(KEY_UNAUTH_RULES);
    if (unauthList != null) {
      for (String s : unauthList) {
        EnforcementRule r = decodeEnforcementRule(s);
        if (r != null) unauthRules.add(r);
      }
    }
    if (!unauthRules.isEmpty()) {
      state.replaceUnauthEnforcementRules(unauthRules, unauthMode);
    } else {
      state.setUnauthEnforcementAndOr(unauthMode);
    }

    // Profiles
    var idsList = root.getStringList(KEY_PROFILE_IDS);
    if (idsList != null && !idsList.isEmpty()) {
      List<UserProfile> profiles = new ArrayList<>();
      for (String id : idsList) {
        PersistedObject po = root.getChildObject(KEY_PROFILE_PREFIX + id);
        if (po == null) continue;
        String name = safeString(po.getString("name"));
        UserProfile p = UserProfile.create(name.isEmpty() ? "User" : name);
        p.setHeadersText(safeString(po.getString("headers")));
        p.setEnforcementAndOr(safeAndOr(po.getString("mode"), p.enforcementAndOr()));

        var mrList = po.getStringList("mr");
        if (mrList != null) {
          for (String s : mrList) {
            MatchReplaceRule mr = decodeMatchReplaceRule(s);
            if (mr != null) p.matchReplaceRules().add(mr);
          }
        }

        var edList = po.getStringList("ed");
        if (edList != null) {
          for (String s : edList) {
            EnforcementRule ed = decodeEnforcementRule(s);
            if (ed != null) p.enforcementRules().add(ed);
          }
        }

        profiles.add(p);
      }
      if (!profiles.isEmpty()) {
        state.replaceAllProfiles(profiles);
      }
    }
  }

  // ---- encoding helpers ----

  private static String safeString(String s) {
    return s == null ? "" : s;
  }

  private static AndOr safeAndOr(String s, AndOr fallback) {
    if (s == null) return fallback;
    try {
      return AndOr.valueOf(s.trim());
    } catch (Exception e) {
      return fallback;
    }
  }

  private static String b64(String s) {
    byte[] bytes = (s == null ? "" : s).getBytes(StandardCharsets.UTF_8);
    return Base64.getEncoder().encodeToString(bytes);
  }

  private static String unb64(String s) {
    try {
      byte[] bytes = Base64.getDecoder().decode(s);
      return new String(bytes, StandardCharsets.UTF_8);
    } catch (Exception e) {
      return "";
    }
  }

  private static String encodeMatchReplaceRule(MatchReplaceRule r) {
    return "t=" + r.type().name() + ";m=" + b64(r.match()) + ";r=" + b64(r.replace());
  }

  private static MatchReplaceRule decodeMatchReplaceRule(String s) {
    if (s == null) return null;
    try {
      String t = getKv(s, "t");
      String m = getKv(s, "m");
      String r = getKv(s, "r");
      MatchReplaceType type = MatchReplaceType.valueOf(t);
      return new MatchReplaceRule(type, unb64(m), unb64(r));
    } catch (Exception e) {
      return null;
    }
  }

  private static String encodeEnforcementRule(EnforcementRule r) {
    return "t=" + r.type().name() + ";inv=" + (r.inverse() ? "1" : "0") + ";c=" + b64(r.content());
  }

  private static EnforcementRule decodeEnforcementRule(String s) {
    if (s == null) return null;
    try {
      String t = getKv(s, "t");
      String inv = getKv(s, "inv");
      String c = getKv(s, "c");
      EnforcementRuleType type = EnforcementRuleType.valueOf(t);
      boolean inverse = "1".equals(inv);
      return new EnforcementRule(type, inverse, unb64(c));
    } catch (Exception e) {
      return null;
    }
  }

  private static String encodeInterceptionFilter(InterceptionFilter f) {
    return "t=" + f.type().name() + ";c=" + b64(f.content());
  }

  private static InterceptionFilter decodeInterceptionFilter(String s) {
    if (s == null) return null;
    try {
      String t = getKv(s, "t");
      String c = getKv(s, "c");
      InterceptionFilterType type = InterceptionFilterType.valueOf(t);
      return new InterceptionFilter(type, unb64(c));
    } catch (Exception e) {
      return null;
    }
  }

  private static String getKv(String s, String key) {
    String[] parts = s.split(";");
    for (String p : parts) {
      int idx = p.indexOf('=');
      if (idx <= 0) continue;
      String k = p.substring(0, idx);
      if (k.equals(key)) {
        return p.substring(idx + 1);
      }
    }
    return "";
  }

  private static burp.api.montoya.persistence.PersistedList<String> persistedStringList(List<String> strings) {
    PersistedList<String> list = PersistedList.persistedStringList();
    if (strings != null) {
      list.addAll(strings);
    }
    return list;
  }
}
