package autorize;

import autorize.core.AutorizeController;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * Montoya API entrypoint.
 *
 * Burp discovers Montoya extensions via Java's ServiceLoader (see src/main/resources/META-INF/services).
 */
public final class Extension implements BurpExtension {
  private final AutorizeController controller = new AutorizeController();

  @Override
  public void initialize(MontoyaApi api) {
    api.extension().setName("Autorize (Java rewrite, Montoya)");

    controller.init(api);
    controller.initUi();

    api.logging().logToOutput("Autorize (Montoya) loaded. Legacy code is in /legacy.");
  }
}

