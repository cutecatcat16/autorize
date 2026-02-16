package autorize.model;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

public final class UserProfile {
  private final UUID id;
  private volatile String name;
  private volatile String headersText;
  private volatile AndOr enforcementAndOr = AndOr.OR;

  private final List<MatchReplaceRule> matchReplaceRules = new CopyOnWriteArrayList<>();
  private final List<EnforcementRule> enforcementRules = new CopyOnWriteArrayList<>();

  private UserProfile(UUID id, String name) {
    this.id = id;
    this.name = name;
    this.headersText = "";
  }

  public static UserProfile create(String name) {
    return new UserProfile(UUID.randomUUID(), name);
  }

  public UUID id() {
    return id;
  }

  public String name() {
    return name;
  }

  public void setName(String name) {
    this.name = name == null ? "" : name;
  }

  public String headersText() {
    return headersText;
  }

  public void setHeadersText(String headersText) {
    this.headersText = headersText == null ? "" : headersText;
  }

  public AndOr enforcementAndOr() {
    return enforcementAndOr;
  }

  public void setEnforcementAndOr(AndOr enforcementAndOr) {
    this.enforcementAndOr = enforcementAndOr == null ? AndOr.OR : enforcementAndOr;
  }

  public List<MatchReplaceRule> matchReplaceRules() {
    return matchReplaceRules;
  }

  public List<EnforcementRule> enforcementRules() {
    return enforcementRules;
  }

  public UserProfile deepCopyWithName(String newName) {
    UserProfile copy = new UserProfile(UUID.randomUUID(), newName);
    copy.setHeadersText(headersText);
    copy.setEnforcementAndOr(enforcementAndOr);
    copy.matchReplaceRules.addAll(matchReplaceRules);
    copy.enforcementRules.addAll(enforcementRules);
    return copy;
  }
}
