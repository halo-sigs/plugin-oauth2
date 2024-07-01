package run.halo.oauth;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.security.LoginHandlerEnhancer;

/**
 * Tests for {@link Oauth2LoginConfiguration}.
 *
 * @author guqing
 * @since 2.0.0
 */
class Oauth2LoginConfigurationTest {

    @Test
    void constructor() {
        ReactiveExtensionClient extensionClient = mock(ReactiveExtensionClient.class);
        var loginHandlerEnhancer = mock(LoginHandlerEnhancer.class);
        Oauth2LoginConfiguration oauth2LoginConfiguration =
            new Oauth2LoginConfiguration(extensionClient, loginHandlerEnhancer);
        assertNotNull(oauth2LoginConfiguration);
    }

}
