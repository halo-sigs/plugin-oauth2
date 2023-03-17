package run.halo.oauth;

import org.pf4j.PluginWrapper;
import org.springframework.stereotype.Component;
import run.halo.app.extension.Scheme;
import run.halo.app.extension.SchemeManager;
import run.halo.app.plugin.BasePlugin;

/**
 * Oauth GitHub plugin.
 *
 * @author guqing
 * @since 1.0.0
 */
@Component
public class OauthGithubPlugin extends BasePlugin {

    private final SchemeManager schemeManager;

    public OauthGithubPlugin(PluginWrapper wrapper, SchemeManager schemeManager) {
        super(wrapper);
        this.schemeManager = schemeManager;
    }

    @Override
    public void start() {
        schemeManager.register(AuthorizedClient.class);
    }

    @Override
    public void stop() {
        schemeManager.unregister(Scheme.buildFromType(AuthorizedClient.class));
    }
}
