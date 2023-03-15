package run.halo.oauth;

import org.springframework.lang.NonNull;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.oauth2.client.web.server.OAuth2AuthorizationRequestRedirectWebFilter;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import run.halo.app.security.AdditionalWebFilter;

/**
 * @author guqing
 * @since 1.0.0
 */
@Component
public class Oauth2AuthorizationRequestRedirectWebFilter implements AdditionalWebFilter {

    private final Oauth2LoginConfiguration oauth2LoginConfiguration;
    private final OAuth2AuthorizationRequestRedirectWebFilter oauthRedirectFilter;

    public Oauth2AuthorizationRequestRedirectWebFilter(
        Oauth2LoginConfiguration oauth2LoginConfiguration) {
        this.oauth2LoginConfiguration = oauth2LoginConfiguration;

        this.oauthRedirectFilter = createAuthenticationWebFilter();
    }

    @Override
    @NonNull
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
        return oauthRedirectFilter.filter(exchange, chain);
    }

    @Override
    public int getOrder() {
        return SecurityWebFiltersOrder.HTTP_BASIC.getOrder() - 1;
    }

    OAuth2AuthorizationRequestRedirectWebFilter createAuthenticationWebFilter() {
        OAuth2AuthorizationRequestRedirectWebFilter oauthRedirectFilter =
            oauth2LoginConfiguration.getRedirectWebFilter();
        ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest>
            authorizationRequestRepository =
            oauth2LoginConfiguration.getAuthorizationRequestRepository();
        oauthRedirectFilter.setAuthorizationRequestRepository(authorizationRequestRepository);
        oauthRedirectFilter.setAuthorizationRedirectStrategy(
            oauth2LoginConfiguration.getAuthorizationRedirectStrategy());
        oauthRedirectFilter.setRequestCache(oauth2LoginConfiguration.getRequestCache());

        return oauthRedirectFilter;
    }
}
