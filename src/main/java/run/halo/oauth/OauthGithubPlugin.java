package run.halo.oauth;

import org.springframework.stereotype.Component;
import run.halo.app.extension.Scheme;
import run.halo.app.extension.SchemeManager;
import run.halo.app.plugin.BasePlugin;
import run.halo.app.plugin.PluginContext;

/**
 * Oauth GitHub plugin.
 *
 * @author guqing
 * @since 1.0.0
 */
@Component
public class OauthGithubPlugin extends BasePlugin {

    private final SchemeManager schemeManager;

    public OauthGithubPlugin(PluginContext pluginContext, SchemeManager schemeManager) {
        super(pluginContext);
        this.schemeManager = schemeManager;
    }

    @Override
    public void start() {
        schemeManager.register(AuthorizedClient.class);
        schemeManager.register(Oauth2ClientRegistration.class);
    }

    @Override
    public void stop() {
        schemeManager.unregister(Scheme.buildFromType(AuthorizedClient.class));
        schemeManager.unregister(Scheme.buildFromType(Oauth2ClientRegistration.class));
    }
}
