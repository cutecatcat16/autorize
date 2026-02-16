package autorize.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import autorize.model.LogEntry;
import autorize.model.AndOr;
import autorize.model.EnforcementRule;
import autorize.model.EnforcementRuleType;
import autorize.model.InterceptionFilter;
import autorize.model.InterceptionFilterType;
import autorize.model.MatchReplaceRule;
import autorize.model.MatchReplaceType;
import autorize.model.UserProfile;
import autorize.ui.AutorizeTab;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Minimal scaffold that will become the Java port of legacy/Autorize.py + legacy/authorization/authorization.py.
 *
 * The key architectural rule we keep from legacy:
 * - Never block/modify the browser's proxy flow by default.
 * - Do replays asynchronously after responses are observed.
 */
public final class AutorizeController implements HttpHandler {
  private static final Pattern DEFAULT_ENFORCED_BODY_REGEX =
      Pattern.compile("(?i)(forbidden|unauthorized|access denied)");
  private static final String DEFAULT_STEPPER_HEADER = "X-Stepper-Execute-Login";

  private MontoyaApi api;
  private ExecutorService executor;

  private final AutorizeState state = new AutorizeState();
  private volatile AutorizeTab tab;
  private final AutorizePersistence persistence = new AutorizePersistence();

  public void init(MontoyaApi api) {
    this.api = api;
    this.executor = Executors.newFixedThreadPool(10);

    // Load saved settings before wiring listeners/UI.
    try {
      persistence.load(api.persistence().extensionData(), state);
    } catch (Throwable t) {
      api.logging().logToError("Autorize: failed to load settings: " + t);
    }

    api.http().registerHttpHandler(this);
    api.proxy().registerRequestHandler(new ProxyRequestHandler() {
      @Override
      public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        // Legacy "Drop proxy listener ports" feature.
        if (shouldDropProxyRequest(interceptedRequest)) {
          return ProxyRequestReceivedAction.drop();
        }
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
      }

      @Override
      public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        // No change on send.
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
      }
    });

    // Auto-save settings on any config/profile change.
    state.addListener(new AutorizeState.Listener() {
      @Override
      public void onProfilesChanged() {
        saveSettings();
      }

      @Override
      public void onLogChanged() {
        // don't persist log
      }

      @Override
      public void onConfigChanged() {
        saveSettings();
      }
    });

    api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
      @Override
      public void extensionUnloaded() {
        executor.shutdown();
      }
    });

    // User preference: start enabled by default when the extension loads.
    state.setEnabled(true);
  }

  public void initUi() {
    if (tab != null) {
      return;
    }
    tab = new AutorizeTab(api, state);
    var panel = tab.build();
    api.userInterface().applyThemeToComponent(panel);
    api.userInterface().registerSuiteTab("Autorize", panel);

    tab.resultsPanel().setRetestHandlers(this::retestRows, this::retestAll);
  }

  public void retestRows(List<Integer> modelRows) {
    if (modelRows == null || modelRows.isEmpty()) return;
    List<LogEntry> snap = state.logSnapshot();
    for (Integer idx : modelRows) {
      if (idx == null) continue;
      int i = idx;
      if (i < 0 || i >= snap.size()) continue;
      LogEntry e = snap.get(i);
      if (e == null || e.original() == null) continue;
      HttpRequestResponse original = e.original().copyToTempFile();
      executor.submit(() -> {
        try {
          processOriginalAsync(original);
        } catch (Throwable t) {
          api.logging().logToError("Autorize retest error: " + t);
        }
      });
    }
  }

  public void retestAll() {
    List<LogEntry> snap = state.logSnapshot();
    for (LogEntry e : snap) {
      if (e == null || e.original() == null) continue;
      HttpRequestResponse original = e.original().copyToTempFile();
      executor.submit(() -> {
        try {
          processOriginalAsync(original);
        } catch (Throwable t) {
          api.logging().logToError("Autorize retest error: " + t);
        }
      });
    }
  }

  private void saveSettings() {
    try {
      persistence.save(api.persistence().extensionData(), state);
    } catch (Throwable t) {
      api.logging().logToError("Autorize: failed to save settings: " + t);
    }
  }

  @Override
  public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
    // Optional: prevent 304 by stripping caching headers from original traffic.
    if (!state.enabled() || !state.prevent304()) {
      return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    // Don't touch our own replays.
    if (requestToBeSent.hasHeader("X-Autorize-Replay")) {
      return RequestToBeSentAction.continueWith(requestToBeSent);
    }

      // Only apply to Proxy (and optionally Repeater).
      ToolType toolType = requestToBeSent.toolSource().toolType();
      if (toolType != ToolType.PROXY) {
        if (!(toolType == ToolType.REPEATER && state.interceptRepeater())) {
          return RequestToBeSentAction.continueWith(requestToBeSent);
        }
      }
      if (toolNeedsToBeIgnored(toolType)) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
      }

    HttpRequest patched = requestToBeSent;
    if (patched.hasHeader("If-None-Match")) {
      patched = patched.withRemovedHeader("If-None-Match");
    }
    if (patched.hasHeader("If-Modified-Since")) {
      patched = patched.withRemovedHeader("If-Modified-Since");
    }
    return RequestToBeSentAction.continueWith(patched);
  }

  @Override
  public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
    if (!state.enabled()) {
      return ResponseReceivedAction.continueWith(responseReceived);
    }

    // Ignore our own replays.
    HttpRequest initiating = responseReceived.initiatingRequest();
    if (initiating != null && initiating.hasHeader("X-Autorize-Replay")) {
      return ResponseReceivedAction.continueWith(responseReceived);
    }

    // Always respect Burp project scope.
    if (!isInProjectScope(initiating)) {
      return ResponseReceivedAction.continueWith(responseReceived);
    }

      // Tool filtering: Proxy always; Repeater only if enabled.
      ToolType toolType = responseReceived.toolSource().toolType();
      if (toolType != ToolType.PROXY) {
        if (!(toolType == ToolType.REPEATER && state.interceptRepeater())) {
          return ResponseReceivedAction.continueWith(responseReceived);
        }
      }
      if (toolNeedsToBeIgnored(toolType)) {
        return ResponseReceivedAction.continueWith(responseReceived);
      }

    if (state.ignore304()) {
      short sc = responseReceived.statusCode();
      if (sc == 304 || sc == 204) {
        return ResponseReceivedAction.continueWith(responseReceived);
      }
    }

    // Interception filters.
    if (!passedInterceptionFilters(responseReceived.initiatingRequest(), responseReceived)) {
      return ResponseReceivedAction.continueWith(responseReceived);
    }

    executor.submit(() -> {
      try {
        processResponseAsync(responseReceived);
      } catch (Throwable t) {
        api.logging().logToError("Autorize error: " + t);
      }
    });

    return ResponseReceivedAction.continueWith(responseReceived);
  }

  private void processResponseAsync(HttpResponseReceived responseReceived) {
    HttpRequest originalReq = responseReceived.initiatingRequest().copyToTempFile();
    HttpResponse originalRes = responseReceived.copyToTempFile();
    HttpRequestResponse original = HttpRequestResponse.httpRequestResponse(originalReq, originalRes).copyToTempFile();
    processOriginalAsync(original);
  }

  private void processOriginalAsync(HttpRequestResponse original) {
    if (original == null) return;
    HttpRequest originalReq = original.request().copyToTempFile();
    HttpResponse originalRes = original.response() == null ? null : original.response().copyToTempFile();
    if (originalRes == null) return;

    int n = state.nextRequestNumber();
    String method = originalReq.method();
    String url = originalReq.url();
    String oldStatus = String.valueOf(originalRes.statusCode());
    byte[] oldBody = safeBodyBytes(originalRes);

    HttpRequestResponse unauth = null;
    String unauthVerdict = "Disabled";
    String unauthStatus = null;
    byte[] unauthBody = null;
    if (state.checkUnauthenticated()) {
      HttpRequest unauthReq = stripAuthHeaders(originalReq)
          .withAddedHeader("X-Autorize-Replay", "1")
          .copyToTempFile();
      unauth = api.http().sendRequest(unauthReq).copyToTempFile();
      unauthStatus = String.valueOf(unauth.response().statusCode());
      unauthBody = safeBodyBytes(unauth.response());
      unauthVerdict = checkBypass(
          oldStatus,
          unauthStatus,
          oldBody,
          unauthBody,
          state.unauthEnforcementRules(),
          state.unauthEnforcementAndOr(),
          unauth.response(),
          null,
          null
      );
    }

    LogEntry entry = new LogEntry(n, method, url, original, unauth, unauthVerdict);

    List<UserProfile> profiles = state.profilesSnapshot();
    for (UserProfile profile : profiles) {
      HttpRequest replayReq = buildReplayRequest(originalReq, profile)
          .withAddedHeader("X-Autorize-Replay", "1")
          .withAddedHeader("X-Autorize-User", profile.name())
          .copyToTempFile();

      HttpRequestResponse rr = api.http().sendRequest(replayReq).copyToTempFile();
      String replayStatus = String.valueOf(rr.response().statusCode());
      byte[] replayBody = safeBodyBytes(rr.response());
      String verdict = checkBypass(
          oldStatus,
          replayStatus,
          oldBody,
          replayBody,
          profile.enforcementRules(),
          profile.enforcementAndOr(),
          rr.response(),
          unauthStatus,
          unauthBody
      );
      entry.putProfileResult(profile.id(), rr, verdict);
    }

    state.addLogEntry(entry);
  }

  private static HttpRequest stripAuthHeaders(HttpRequest req) {
    HttpRequest r = req;
    if (r.hasHeader("Cookie")) r = r.withRemovedHeader("Cookie");
    if (r.hasHeader("Authorization")) r = r.withRemovedHeader("Authorization");
    if (r.hasHeader("X-Autorize-Replay")) r = r.withRemovedHeader("X-Autorize-Replay");
    if (r.hasHeader("X-Autorize-User")) r = r.withRemovedHeader("X-Autorize-User");
    return r;
  }

  public void submitToAutorize(List<HttpRequestResponse> selected) {
    if (selected == null || selected.isEmpty()) return;
    for (HttpRequestResponse rr : selected) {
      if (rr == null) continue;
      HttpRequestResponse copy = rr.copyToTempFile();
      executor.submit(() -> {
        try {
          submitSingleToAutorize(copy);
        } catch (Throwable t) {
          api.logging().logToError("Autorize submit error: " + t);
        }
      });
    }
  }

  private void submitSingleToAutorize(HttpRequestResponse rr) {
    if (rr == null) return;
    HttpRequest req = rr.request().copyToTempFile();
    if (!isInProjectScope(req)) {
      return;
    }
    HttpResponse res = rr.response();
    if (res == null) {
      // No response available from the invocation context, fetch it first.
      HttpRequest replayReq = req.withAddedHeader("X-Autorize-Replay", "1").copyToTempFile();
      HttpRequestResponse fetched = api.http().sendRequest(replayReq).copyToTempFile();
      // Respect the same interception filters as the live pipeline (including scope-only).
      if (fetched != null && fetched.request() != null && fetched.response() != null) {
        if (!isInProjectScope(fetched.request())) return;
        if (state.ignore304()) {
          short sc = fetched.response().statusCode();
          if (sc == 304 || sc == 204) return;
        }
        if (!passedInterceptionFilters(fetched.request(), fetched.response())) return;
      }
      processOriginalAsync(fetched);
      return;
    }
    // Respect the same interception filters as the live pipeline (including scope-only).
    if (state.ignore304()) {
      short sc = res.statusCode();
      if (sc == 304 || sc == 204) return;
    }
    if (!passedInterceptionFilters(req, res)) return;
    processOriginalAsync(rr.copyToTempFile());
  }

  private HttpRequest buildReplayRequest(HttpRequest original, UserProfile profile) {
    HttpRequest r = original;

    // Apply match/replace rules first.
    r = applyMatchReplace(r, profile.matchReplaceRules());

    // Optional legacy "replace query param" (applies to replays).
    r = applyQueryParamReplace(r);

    // Then apply explicit headers, with replace semantics.
    List<HttpHeader> headers = parseHeaders(profile.headersText());
    for (HttpHeader h : headers) {
      if (r.hasHeader(h.name())) {
        r = r.withRemovedHeader(h.name());
      }
      r = r.withAddedHeader(h);
    }
    // Ensure stepper header overrides are applied last.
    r = applyStepperHeaderRules(r, profile.matchReplaceRules());
    return r;
  }

  private HttpRequest applyQueryParamReplace(HttpRequest req) {
    if (!state.replaceQueryParam()) {
      return req;
    }
    String t = state.replaceQueryParamText();
    int idx = t.indexOf('=');
    if (idx <= 0) return req;
    String key = t.substring(0, idx).trim();
    String val = t.substring(idx + 1).trim();
    if (key.isEmpty()) return req;

    HttpParameter p = HttpParameter.urlParameter(key, val);
    if (req.hasParameter(key, HttpParameterType.URL)) {
      return req.withUpdatedParameters(p);
    }
    return req.withAddedParameters(p);
  }

  private static HttpRequest applyMatchReplace(HttpRequest req, List<MatchReplaceRule> rules) {
    if (rules == null || rules.isEmpty()) return req;

    HttpRequest r = req;

    // Path modifications.
    String path = r.path();
    for (MatchReplaceRule rule : rules) {
      if (rule.type() == MatchReplaceType.PATH_SIMPLE) {
        path = path.replace(rule.match(), rule.replace());
      } else if (rule.type() == MatchReplaceType.PATH_REGEX && rule.regex() != null) {
        path = rule.regex().matcher(path).replaceAll(rule.replace());
      }
    }
    r = r.withPath(path);

    // Header replace by header name/value (legacy-compatible explicit mode).
    for (MatchReplaceRule rule : rules) {
      if (rule.type() != MatchReplaceType.HEADER_REPLACE) continue;
      String headerName = rule.match() == null ? "" : rule.match().trim();
      if (headerName.isEmpty()) continue;
      if (r.hasHeader(headerName)) {
        r = r.withRemovedHeader(headerName);
      }
      r = r.withAddedHeader(HttpHeader.httpHeader(headerName, rule.replace()));
    }

    // Cookie replace by cookie name/value inside Cookie header(s).
    for (MatchReplaceRule rule : rules) {
      if (rule.type() != MatchReplaceType.COOKIE_REPLACE) continue;
      String cookieName = rule.match() == null ? "" : rule.match().trim();
      if (cookieName.isEmpty()) continue;
      r = replaceCookieValue(r, cookieName, rule.replace());
    }

    // Header regex/simple transformations (kept for backward compatibility).
    List<HttpHeader> hdrs = new ArrayList<>(r.headers());
    for (int i = 0; i < hdrs.size(); i++) {
      HttpHeader h = hdrs.get(i);
      String s = h.toString();
      for (MatchReplaceRule rule : rules) {
        if (rule.type() == MatchReplaceType.HEADERS_SIMPLE) {
          s = s.replace(rule.match(), rule.replace());
        } else if (rule.type() == MatchReplaceType.HEADERS_REGEX && rule.regex() != null) {
          s = rule.regex().matcher(s).replaceAll(rule.replace());
        }
      }
      HttpHeader parsed = parseHeaderLine(s);
      if (parsed != null) {
        hdrs.set(i, parsed);
      }
    }
    r = r.withUpdatedHeaders(hdrs);

    // Body modifications.
    String body = r.bodyToString();
    if (body != null) {
      for (MatchReplaceRule rule : rules) {
        if (rule.type() == MatchReplaceType.BODY_SIMPLE) {
          body = body.replace(rule.match(), rule.replace());
        } else if (rule.type() == MatchReplaceType.BODY_REGEX && rule.regex() != null) {
          body = rule.regex().matcher(body).replaceAll(rule.replace());
        }
      }
      r = r.withBody(body);
    }

    return r;
  }

  private static HttpRequest applyStepperHeaderRules(HttpRequest request, List<MatchReplaceRule> rules) {
    if (request == null || rules == null || rules.isEmpty()) return request;
    HttpRequest r = request;
    for (MatchReplaceRule rule : rules) {
      if (rule.type() != MatchReplaceType.STEPPER_HEADER) continue;
      if (r.hasHeader(DEFAULT_STEPPER_HEADER)) {
        r = r.withRemovedHeader(DEFAULT_STEPPER_HEADER);
      }
      r = r.withAddedHeader(HttpHeader.httpHeader(DEFAULT_STEPPER_HEADER, rule.replace()));
    }
    return r;
  }

  private static HttpRequest replaceCookieValue(HttpRequest request, String cookieName, String newValue) {
    if (request == null || cookieName == null || cookieName.isEmpty()) {
      return request;
    }

    List<HttpHeader> headers = new ArrayList<>(request.headers());
    boolean touchedAnyCookieHeader = false;
    boolean replaced = false;

    for (int i = 0; i < headers.size(); i++) {
      HttpHeader h = headers.get(i);
      if (h == null) continue;
      String name = h.name();
      if (name == null || !"cookie".equalsIgnoreCase(name.trim())) continue;

      touchedAnyCookieHeader = true;
      String value = h.value() == null ? "" : h.value();
      String updated = replaceCookieInHeaderValue(value, cookieName, newValue);
      if (!value.equals(updated)) {
        replaced = true;
        headers.set(i, HttpHeader.httpHeader(h.name(), updated));
      }
    }

    if (!touchedAnyCookieHeader) {
      headers.add(HttpHeader.httpHeader("Cookie", cookieName + "=" + (newValue == null ? "" : newValue)));
      return request.withUpdatedHeaders(headers);
    }

    if (!replaced) {
      for (int i = 0; i < headers.size(); i++) {
        HttpHeader h = headers.get(i);
        if (h == null || h.name() == null) continue;
        if (!"cookie".equalsIgnoreCase(h.name().trim())) continue;
        String value = h.value() == null ? "" : h.value().trim();
        String append = cookieName + "=" + (newValue == null ? "" : newValue);
        String merged = value.isEmpty() ? append : value + "; " + append;
        headers.set(i, HttpHeader.httpHeader(h.name(), merged));
        break;
      }
    }

    return request.withUpdatedHeaders(headers);
  }

  private static String replaceCookieInHeaderValue(String cookieHeaderValue, String cookieName, String newValue) {
    if (cookieHeaderValue == null || cookieHeaderValue.isEmpty()) {
      return cookieName + "=" + (newValue == null ? "" : newValue);
    }

    String[] parts = cookieHeaderValue.split(";");
    boolean replaced = false;
    for (int i = 0; i < parts.length; i++) {
      String part = parts[i].trim();
      if (part.isEmpty()) continue;
      int eq = part.indexOf('=');
      if (eq <= 0) continue;
      String name = part.substring(0, eq).trim();
      if (!name.equals(cookieName)) continue;
      parts[i] = cookieName + "=" + (newValue == null ? "" : newValue);
      replaced = true;
      break;
    }

    if (!replaced) {
      return cookieHeaderValue.trim() + "; " + cookieName + "=" + (newValue == null ? "" : newValue);
    }

    StringBuilder out = new StringBuilder();
    for (String raw : parts) {
      String t = raw.trim();
      if (t.isEmpty()) continue;
      if (out.length() > 0) out.append("; ");
      out.append(t);
    }
    return out.toString();
  }

  private static List<HttpHeader> parseHeaders(String headersText) {
    List<HttpHeader> out = new ArrayList<>();
    if (headersText == null) return out;
    String[] lines = headersText.split("\\r?\\n");
    for (String raw : lines) {
      String line = raw.trim();
      if (line.isEmpty()) continue;
      int idx = line.indexOf(':');
      if (idx <= 0) continue;
      String name = line.substring(0, idx).trim();
      String value = line.substring(idx + 1).trim();
      if (name.isEmpty()) continue;
      out.add(HttpHeader.httpHeader(name, value));
    }
    return out;
  }

  private static HttpHeader parseHeaderLine(String line) {
    if (line == null) return null;
    int idx = line.indexOf(':');
    if (idx <= 0) return null;
    String name = line.substring(0, idx).trim();
    String value = line.substring(idx + 1).trim();
    if (name.isEmpty()) return null;
    return HttpHeader.httpHeader(name, value);
  }

  private boolean passedInterceptionFilters(HttpRequest req, HttpResponse res) {
    if (req == null || res == null) return false;
    String url = req.url();
    String method = req.method();
    String reqBody = req.bodyToString();
    String resBody = res == null ? "" : safeBody(res);

    for (InterceptionFilter f : state.interceptionFilters()) {
      InterceptionFilterType t = f.type();
      String c = f.content();

      if (t == InterceptionFilterType.SCOPE_ONLY) {
        if (!isInProjectScope(req)) return false;
      } else if (t == InterceptionFilterType.URL_CONTAINS) {
        if (url == null || !url.contains(c)) return false;
      } else if (t == InterceptionFilterType.URL_REGEX) {
        Pattern p = f.regex();
        if (p == null || url == null || !p.matcher(url).find()) return false;
      } else if (t == InterceptionFilterType.URL_NOT_CONTAINS) {
        if (url != null && url.contains(c)) return false;
      } else if (t == InterceptionFilterType.URL_NOT_REGEX) {
        Pattern p = f.regex();
        if (p != null && url != null && p.matcher(url).find()) return false;
      } else if (t == InterceptionFilterType.REQ_BODY_CONTAINS) {
        if (reqBody == null || !reqBody.contains(c)) return false;
      } else if (t == InterceptionFilterType.REQ_BODY_REGEX) {
        Pattern p = f.regex();
        if (p == null || reqBody == null || !p.matcher(reqBody).find()) return false;
      } else if (t == InterceptionFilterType.REQ_BODY_NOT_CONTAINS) {
        if (reqBody != null && reqBody.contains(c)) return false;
      } else if (t == InterceptionFilterType.REQ_BODY_NOT_REGEX) {
        Pattern p = f.regex();
        if (p != null && reqBody != null && p.matcher(reqBody).find()) return false;
      } else if (t == InterceptionFilterType.RES_BODY_CONTAINS) {
        if (resBody == null || !resBody.contains(c)) return false;
      } else if (t == InterceptionFilterType.RES_BODY_REGEX) {
        Pattern p = f.regex();
        if (p == null || resBody == null || !p.matcher(resBody).find()) return false;
      } else if (t == InterceptionFilterType.RES_BODY_NOT_CONTAINS) {
        if (resBody != null && resBody.contains(c)) return false;
      } else if (t == InterceptionFilterType.RES_BODY_NOT_REGEX) {
        Pattern p = f.regex();
        if (p != null && resBody != null && p.matcher(resBody).find()) return false;
      } else if (t == InterceptionFilterType.REQ_HEADER_CONTAINS) {
        boolean any = false;
        for (HttpHeader h : req.headers()) {
          if (h.toString().contains(c)) {
            any = true;
            break;
          }
        }
        if (!any) return false;
      } else if (t == InterceptionFilterType.REQ_HEADER_NOT_CONTAINS) {
        for (HttpHeader h : req.headers()) {
          if (h.toString().contains(c)) return false;
        }
      } else if (t == InterceptionFilterType.RES_HEADER_CONTAINS) {
        boolean any = false;
        if (res != null) {
          for (HttpHeader h : res.headers()) {
            if (h.toString().contains(c)) {
              any = true;
              break;
            }
          }
        }
        if (!any) return false;
      } else if (t == InterceptionFilterType.RES_HEADER_NOT_CONTAINS) {
        if (res != null) {
          for (HttpHeader h : res.headers()) {
            if (h.toString().contains(c)) return false;
          }
        }
      } else if (t == InterceptionFilterType.ONLY_METHODS) {
        String[] ms = c.split("[\\r\\n,]+");
        boolean ok = false;
        for (String m : ms) {
          if (method.equalsIgnoreCase(m.trim())) {
            ok = true;
            break;
          }
        }
        if (!ok) return false;
      } else if (t == InterceptionFilterType.IGNORE_METHODS) {
        String[] ms = c.split("[\\r\\n,]+");
        for (String m : ms) {
          if (method.equalsIgnoreCase(m.trim())) return false;
        }
      } else if (t == InterceptionFilterType.IGNORE_OPTIONS) {
        if ("OPTIONS".equalsIgnoreCase(method)) return false;
      } else if (t == InterceptionFilterType.DROP_PROXY_PORTS) {
        // Handled by proxy handler.
      } else if (t == InterceptionFilterType.IGNORE_PROXY
          || t == InterceptionFilterType.IGNORE_TARGET) {
        // Tool filters are handled earlier in the pipeline.
      }
    }

    return true;
  }

  private boolean toolNeedsToBeIgnored(ToolType toolType) {
    if (toolType == null) return false;
    for (InterceptionFilter f : state.interceptionFilters()) {
      if (f.type() == InterceptionFilterType.IGNORE_PROXY && toolType == ToolType.PROXY) return true;
      if (f.type() == InterceptionFilterType.IGNORE_TARGET && toolType == ToolType.TARGET) return true;
    }
    return false;
  }

  private boolean isInProjectScope(HttpRequest req) {
    if (req == null) return false;

    // Prefer Burp's scope engine, using the URL Burp attaches to the message.
    try {
      String url = req.url();
      if (url != null && !url.isEmpty()) {
        return api.scope().isInScope(url);
      }
    } catch (Exception ignored) {
    }

    // Fallback: build URL from service + path.
    try {
      var svc = req.httpService();
      if (svc != null) {
        String scheme = svc.secure() ? "https" : "http";
        String host = svc.host();
        int port = svc.port();
        String path = req.path();
        if (path == null || path.isEmpty()) path = "/";

        boolean defaultPort = (svc.secure() && port == 443) || (!svc.secure() && port == 80);
        String built = defaultPort
            ? (scheme + "://" + host + path)
            : (scheme + "://" + host + ":" + port + path);
        return api.scope().isInScope(built);
      }
    } catch (Exception ignored) {
    }

    // Final fallback to message flag.
    try {
      return req.isInScope();
    } catch (Exception ignored) {
      return false;
    }
  }

  private static String safeBody(HttpResponse res) {
    try {
      return res == null ? "" : res.bodyToString();
    } catch (Throwable t) {
      return "";
    }
  }

  private static byte[] safeBodyBytes(HttpResponse res) {
    try {
      if (res == null) return new byte[0];
      return res.body().getBytes();
    } catch (Throwable t) {
      return new byte[0];
    }
  }

  private static String checkBypass(
      String oldStatus,
      String newStatus,
      byte[] oldBody,
      byte[] newBody,
      List<EnforcementRule> rules,
      AndOr mode,
      HttpResponse replayResponse,
      String unauthStatus,
      byte[] unauthBody
  ) {
    // Strong enforced defaults first.
    if (isDefaultAuthEnforcedStatus(newStatus)) {
      return "Enforced!";
    }

    String replayBody = safeBody(replayResponse);
    if (replayBody != null && DEFAULT_ENFORCED_BODY_REGEX.matcher(replayBody).find()) {
      return "Enforced!";
    }

    // Optional custom enforcement rules.
    if (rules != null && !rules.isEmpty() && authEnforcedViaRules(rules, replayResponse, mode)) {
      return "Enforced!";
    }

    // Simplified bypass signal: same status as original.
    if (oldStatus != null && oldStatus.equals(newStatus)) {
      return "Bypassed!";
    }

    // Otherwise unknown/inconclusive.
    return "Is enforced???";
  }

  private static boolean isDefaultAuthEnforcedStatus(String status) {
    if (status == null) return false;
    String s = status.trim();
    return "401".equals(s) || "403".equals(s);
  }

  private static boolean authEnforcedViaRules(List<EnforcementRule> rules, HttpResponse response, AndOr mode) {
    if (rules == null || rules.isEmpty() || response == null) return false;

    boolean andMode = mode == AndOr.AND;
    boolean authEnforced = andMode;

    String headersStr = null;
    String bodyStr = null;
    String fullStr = null;

    for (EnforcementRule r : rules) {
      boolean matched = false;
      EnforcementRuleType t = r.type();
      String c = r.content();

      if (t == EnforcementRuleType.STATUS_EQUALS) {
        matched = String.valueOf(response.statusCode()).trim().equals(c.trim());
      } else if (t == EnforcementRuleType.HEADERS_CONTAINS) {
        if (headersStr == null) headersStr = joinHeaders(response.headers());
        matched = headersStr.contains(c);
      } else if (t == EnforcementRuleType.HEADERS_REGEX) {
        if (headersStr == null) headersStr = joinHeaders(response.headers());
        matched = r.regex() != null && r.regex().matcher(headersStr).find();
      } else if (t == EnforcementRuleType.BODY_CONTAINS) {
        if (bodyStr == null) bodyStr = safeBody(response);
        matched = bodyStr.contains(c);
      } else if (t == EnforcementRuleType.BODY_REGEX) {
        if (bodyStr == null) bodyStr = safeBody(response);
        matched = r.regex() != null && r.regex().matcher(bodyStr).find();
      } else if (t == EnforcementRuleType.FULL_CONTAINS) {
        if (fullStr == null) fullStr = response.toString();
        matched = fullStr.contains(c);
      } else if (t == EnforcementRuleType.FULL_REGEX) {
        if (fullStr == null) fullStr = response.toString();
        matched = r.regex() != null && r.regex().matcher(fullStr).find();
      } else if (t == EnforcementRuleType.FULL_LENGTH_EQUALS) {
        int len = response.toByteArray().length();
        matched = String.valueOf(len).trim().equals(c.trim());
      }

      if (r.inverse()) {
        matched = !matched;
      }

      if (andMode) {
        if (!matched) return false;
      } else {
        if (matched) return true;
      }
    }

    return authEnforced;
  }

  private static String joinHeaders(List<HttpHeader> headers) {
    StringBuilder sb = new StringBuilder();
    for (HttpHeader h : headers) {
      sb.append(h.toString()).append("\r\n");
    }
    return sb.toString();
  }

  private boolean shouldDropProxyRequest(InterceptedRequest req) {
    if (req == null) return false;
    int port = parseListenerPort(req.listenerInterface());
    if (port <= 0) return false;

    for (InterceptionFilter f : state.interceptionFilters()) {
      if (f.type() != InterceptionFilterType.DROP_PROXY_PORTS) continue;
      for (int p : parsePorts(f.content())) {
        if (p == port) return true;
      }
    }
    return false;
  }

  private static int parseListenerPort(String listenerInterface) {
    if (listenerInterface == null) return -1;
    int idx = listenerInterface.lastIndexOf(':');
    if (idx < 0) return -1;
    try {
      return Integer.parseInt(listenerInterface.substring(idx + 1).trim());
    } catch (Exception e) {
      return -1;
    }
  }

  private static int[] parsePorts(String s) {
    if (s == null) return new int[0];
    String[] parts = s.split(",");
    int[] out = new int[parts.length];
    int n = 0;
    for (String p : parts) {
      try {
        String t = p.trim();
        if (t.isEmpty()) continue;
        out[n++] = Integer.parseInt(t);
      } catch (Exception ignored) {
      }
    }
    int[] trimmed = new int[n];
    System.arraycopy(out, 0, trimmed, 0, n);
    return trimmed;
  }
}
