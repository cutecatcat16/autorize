package autorize.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public final class LogEntry {
  private final int number;
  private final String method;
  private final String url;

  private final HttpRequestResponse original;
  private final HttpRequestResponse unauthenticated;
  private final Map<UUID, HttpRequestResponse> perProfile = new LinkedHashMap<>();
  private final Map<UUID, String> perProfileVerdict = new LinkedHashMap<>();
  private String unauthVerdict;

  public LogEntry(
      int number,
      String method,
      String url,
      HttpRequestResponse original,
      HttpRequestResponse unauthenticated,
      String unauthVerdict
  ) {
    this.number = number;
    this.method = method;
    this.url = url;
    this.original = original;
    this.unauthenticated = unauthenticated;
    this.unauthVerdict = unauthVerdict;
  }

  public int number() {
    return number;
  }

  public String method() {
    return method;
  }

  public String url() {
    return url;
  }

  public HttpRequestResponse original() {
    return original;
  }

  public HttpRequestResponse unauthenticated() {
    return unauthenticated;
  }

  public String unauthVerdict() {
    return unauthVerdict;
  }

  public void setUnauthVerdict(String verdict) {
    this.unauthVerdict = verdict;
  }

  public void putProfileResult(UUID profileId, HttpRequestResponse rr, String verdict) {
    perProfile.put(profileId, rr);
    perProfileVerdict.put(profileId, verdict);
  }

  public Map<UUID, HttpRequestResponse> perProfile() {
    return perProfile;
  }

  public Map<UUID, String> perProfileVerdict() {
    return perProfileVerdict;
  }
}

