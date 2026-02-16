package autorize.model;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class InterceptionFilter {
  private final InterceptionFilterType type;
  private final String content;
  private final Pattern regex;

  public InterceptionFilter(InterceptionFilterType type, String content) {
    this.type = type;
    this.content = content == null ? "" : content;
    this.regex = compileIfRegex(type, this.content);
  }

  public InterceptionFilterType type() {
    return type;
  }

  public String content() {
    return content;
  }

  public Pattern regex() {
    return regex;
  }

  private static Pattern compileIfRegex(InterceptionFilterType type, String content) {
    if (type != InterceptionFilterType.URL_REGEX
        && type != InterceptionFilterType.URL_NOT_REGEX
        && type != InterceptionFilterType.REQ_BODY_REGEX
        && type != InterceptionFilterType.REQ_BODY_NOT_REGEX
        && type != InterceptionFilterType.RES_BODY_REGEX
        && type != InterceptionFilterType.RES_BODY_NOT_REGEX) {
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
    return type + " | " + content;
  }
}
