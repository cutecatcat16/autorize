package autorize.model;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class EnforcementRule {
  private final EnforcementRuleType type;
  private final boolean inverse;
  private final String content;
  private final Pattern regex;

  public EnforcementRule(EnforcementRuleType type, boolean inverse, String content) {
    this.type = type;
    this.inverse = inverse;
    this.content = content == null ? "" : content;
    this.regex = compileIfRegex(type, this.content);
  }

  public EnforcementRuleType type() {
    return type;
  }

  public boolean inverse() {
    return inverse;
  }

  public String content() {
    return content;
  }

  public Pattern regex() {
    return regex;
  }

  private static Pattern compileIfRegex(EnforcementRuleType type, String content) {
    if (type != EnforcementRuleType.HEADERS_REGEX
        && type != EnforcementRuleType.BODY_REGEX
        && type != EnforcementRuleType.FULL_REGEX) {
      return null;
    }
    try {
      return Pattern.compile(content, Pattern.CASE_INSENSITIVE);
    } catch (PatternSyntaxException e) {
      return null;
    }
  }

  @Override
  public String toString() {
    String not = inverse ? "NOT " : "";
    return not + type + " | " + content;
  }
}
