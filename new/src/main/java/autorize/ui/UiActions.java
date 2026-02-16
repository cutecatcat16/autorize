package autorize.ui;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;

public interface UiActions {
  void sendToRepeater(HttpRequest request, String tabName);
  void sendToComparer(ByteArray... items);
}

