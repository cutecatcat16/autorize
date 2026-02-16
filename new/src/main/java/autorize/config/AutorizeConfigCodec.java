package autorize.config;

import autorize.core.AutorizeState;
import autorize.model.AndOr;
import autorize.model.EnforcementRule;
import autorize.model.EnforcementRuleType;
import autorize.model.InterceptionFilter;
import autorize.model.InterceptionFilterType;
import autorize.model.MatchReplaceRule;
import autorize.model.MatchReplaceType;
import autorize.model.UserProfile;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class AutorizeConfigCodec {
  private static final ObjectMapper MAPPER = new ObjectMapper()
      .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

  private AutorizeConfigCodec() {}

  public static String toJson(AutorizeState state) throws IOException {
    AutorizeConfig cfg = fromState(state);
    return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(cfg);
  }

  public static void applyJsonToState(String json, AutorizeState state) throws IOException {
    AutorizeConfig cfg = MAPPER.readValue(json, AutorizeConfig.class);
    applyToState(cfg, state);
  }

  public static AutorizeConfig fromState(AutorizeState state) {
    AutorizeConfig cfg = new AutorizeConfig();
    cfg.interceptRepeater = state.interceptRepeater();
    cfg.checkUnauthenticated = state.checkUnauthenticated();
    cfg.ignore304 = state.ignore304();
    cfg.prevent304 = state.prevent304();
    cfg.autoScroll = state.autoScroll();
    cfg.replaceQueryParam = state.replaceQueryParam();
    cfg.replaceQueryParamText = state.replaceQueryParamText();
    cfg.showBypassed = state.showBypassed();
    cfg.showEnforced = state.showEnforced();
    cfg.showUnknown = state.showUnknown();

    for (InterceptionFilter f : state.interceptionFilters()) {
      AutorizeConfig.InterceptionFilterConfig fc = new AutorizeConfig.InterceptionFilterConfig();
      fc.type = f.type().name();
      fc.content = f.content();
      cfg.interceptionFilters.add(fc);
    }

    cfg.unauthDetector.mode = state.unauthEnforcementAndOr().name();
    for (var r : state.unauthEnforcementRules()) {
      cfg.unauthDetector.rules.add(ruleCfg(r));
    }

    for (UserProfile p : state.profilesSnapshot()) {
      AutorizeConfig.UserProfileConfig pc = new AutorizeConfig.UserProfileConfig();
      pc.name = p.name();
      pc.headersText = p.headersText();
      pc.enforcementMode = p.enforcementAndOr().name();
      for (MatchReplaceRule mr : p.matchReplaceRules()) {
        AutorizeConfig.MatchReplaceConfig mrc = new AutorizeConfig.MatchReplaceConfig();
        mrc.type = mr.type().name();
        mrc.match = mr.match();
        mrc.replace = mr.replace();
        pc.matchReplace.add(mrc);
      }
      for (EnforcementRule er : p.enforcementRules()) {
        pc.enforcementRules.add(ruleCfg(er));
      }
      cfg.profiles.add(pc);
    }

    return cfg;
  }

  private static AutorizeConfig.RuleConfig ruleCfg(EnforcementRule r) {
    AutorizeConfig.RuleConfig rc = new AutorizeConfig.RuleConfig();
    rc.type = r.type().name();
    rc.inverse = r.inverse();
    rc.content = r.content();
    return rc;
  }

  public static void applyToState(AutorizeConfig cfg, AutorizeState state) {
    if (cfg == null) return;
    if (cfg.version != 1) {
      throw new IllegalArgumentException("Unsupported config version: " + cfg.version);
    }

    // Safety: importing config should not enable interception automatically.
    state.setEnabled(false);

    state.setInterceptRepeater(cfg.interceptRepeater);
    state.setCheckUnauthenticated(cfg.checkUnauthenticated);
    state.setIgnore304(cfg.ignore304);
    state.setPrevent304(cfg.prevent304);
    state.setAutoScroll(cfg.autoScroll);
    state.setReplaceQueryParam(cfg.replaceQueryParam);
    if (cfg.replaceQueryParamText != null) {
      state.setReplaceQueryParamText(cfg.replaceQueryParamText);
    }
    state.setShowBypassed(cfg.showBypassed);
    state.setShowEnforced(cfg.showEnforced);
    state.setShowUnknown(cfg.showUnknown);

    // Interception filters
    List<InterceptionFilter> filters = new ArrayList<>();
    if (cfg.interceptionFilters != null) {
      for (var fc : cfg.interceptionFilters) {
        InterceptionFilterType t = safeEnum(InterceptionFilterType.class, fc.type, null);
        if (t == null) continue;
        filters.add(new InterceptionFilter(t, fc.content));
      }
    }
    state.replaceInterceptionFilters(filters);

    // Unauth detector
    AndOr unauthMode = safeEnum(AndOr.class, cfg.unauthDetector == null ? null : cfg.unauthDetector.mode, AndOr.OR);
    List<EnforcementRule> unauthRules = new ArrayList<>();
    if (cfg.unauthDetector != null && cfg.unauthDetector.rules != null) {
      for (var rc : cfg.unauthDetector.rules) {
        EnforcementRuleType t = safeEnum(EnforcementRuleType.class, rc.type, null);
        if (t == null) continue;
        unauthRules.add(new EnforcementRule(t, rc.inverse, rc.content));
      }
    }
    state.replaceUnauthEnforcementRules(unauthRules, unauthMode);

    // Profiles
    List<UserProfile> profiles = new ArrayList<>();
    if (cfg.profiles != null && !cfg.profiles.isEmpty()) {
      for (var pc : cfg.profiles) {
        UserProfile p = UserProfile.create(pc.name == null ? "" : pc.name);
        p.setHeadersText(pc.headersText);
        p.setEnforcementAndOr(safeEnum(AndOr.class, pc.enforcementMode, AndOr.OR));

        if (pc.matchReplace != null) {
          for (var mrc : pc.matchReplace) {
            MatchReplaceType mt = safeEnum(MatchReplaceType.class, mrc.type, null);
            if (mt == null) continue;
            p.matchReplaceRules().add(new MatchReplaceRule(mt, mrc.match, mrc.replace));
          }
        }

        if (pc.enforcementRules != null) {
          for (var rc : pc.enforcementRules) {
            EnforcementRuleType t = safeEnum(EnforcementRuleType.class, rc.type, null);
            if (t == null) continue;
            p.enforcementRules().add(new EnforcementRule(t, rc.inverse, rc.content));
          }
        }

        profiles.add(p);
      }
    }
    state.replaceAllProfiles(profiles);
  }

  private static <E extends Enum<E>> E safeEnum(Class<E> cls, String v, E fallback) {
    if (v == null) return fallback;
    try {
      return Enum.valueOf(cls, v.trim());
    } catch (Exception e) {
      return fallback;
    }
  }
}
