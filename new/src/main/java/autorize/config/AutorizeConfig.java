package autorize.config;

import java.util.ArrayList;
import java.util.List;

/**
 * JSON-serializable configuration snapshot.
 *
 * Intentionally excludes runtime-only fields like "enabled" and the results table.
 */
public final class AutorizeConfig {
  public int version = 1;

  public boolean interceptRepeater = false;
  public boolean checkUnauthenticated = true;
  public boolean ignore304 = true;
  public boolean prevent304 = false;
  public boolean autoScroll = false;
  public boolean replaceQueryParam = false;
  public String replaceQueryParamText = "paramName=paramValue";
  public boolean showBypassed = true;
  public boolean showEnforced = true;
  public boolean showUnknown = true;

  public List<InterceptionFilterConfig> interceptionFilters = new ArrayList<>();

  public UnauthDetectorConfig unauthDetector = new UnauthDetectorConfig();

  public List<UserProfileConfig> profiles = new ArrayList<>();

  public static final class InterceptionFilterConfig {
    public String type;
    public String content;
  }

  public static final class RuleConfig {
    public String type;
    public boolean inverse;
    public String content;
  }

  public static final class MatchReplaceConfig {
    public String type;
    public String match;
    public String replace;
  }

  public static final class UnauthDetectorConfig {
    public String mode = "OR";
    public List<RuleConfig> rules = new ArrayList<>();
  }

  public static final class UserProfileConfig {
    public String name;
    public String headersText;
    public String enforcementMode = "OR";
    public List<MatchReplaceConfig> matchReplace = new ArrayList<>();
    public List<RuleConfig> enforcementRules = new ArrayList<>();
  }
}
