package autorize.model;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class MatchReplaceRule {
  private final MatchReplaceType type;
  private final String match;
  private final String replace;
  private final Pattern regex;

  public MatchReplaceRule(MatchReplaceType type, String match, String replace) {
    this.type = type;
    this.match = match == null ? "" : match;
    this.replace = replace == null ? "" : replace;
    this.regex = compileIfRegex(type, this.match);
  }

  public MatchReplaceType type() {
    return type;
  }

  public String match() {
    return match;
  }

  public String replace() {
    return replace;
  }

  public Pattern regex() {
    return regex;
  }

  public static Pattern compileIfRegex(MatchReplaceType type, String match) {
    if (type != MatchReplaceType.HEADERS_REGEX
        && type != MatchReplaceType.BODY_REGEX
        && type != MatchReplaceType.PATH_REGEX) {
      return null;
    }
    try {
      return Pattern.compile(match);
    } catch (PatternSyntaxException e) {
      return null;
    }
  }

  @Override
  public String toString() {
    return type + " | " + match + " -> " + replace;
  }
}
