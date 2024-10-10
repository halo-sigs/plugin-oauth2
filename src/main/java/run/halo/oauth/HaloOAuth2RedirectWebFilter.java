package run.halo.oauth;

import org.springframework.security.oauth2.client.web.server.OAuth2AuthorizationRequestRedirectWebFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import run.halo.app.security.HttpBasicSecurityWebFilter;

@Component
public class HaloOAuth2RedirectWebFilter implements HttpBasicSecurityWebFilter {

    private final WebFilter delegate;

    public HaloOAuth2RedirectWebFilter(Oauth2LoginConfiguration configuration) {
        this.delegate = createDelegate(configuration);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return delegate.filter(exchange, chain);
    }

    private static OAuth2AuthorizationRequestRedirectWebFilter createDelegate(
        Oauth2LoginConfiguration configuration
    ) {
        return new OAuth2AuthorizationRequestRedirectWebFilter(
            configuration.getClientRegistrationRepository()
        );
    }

}
