package run.halo.oauth;

import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationCodeAuthenticationTokenConverter;
import org.springframework.security.oauth2.client.web.server.authentication.OAuth2LoginAuthenticationWebFilter;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import run.halo.app.security.AuthenticationSecurityWebFilter;

/**
 * OAuth2 authentication web filter.
 *
 * @author johnniang
 * @since 2.20.0
 */
@Component
public class HaloOAuth2AuthenticationWebFilter implements AuthenticationSecurityWebFilter {

    private final WebFilter delegate;

    public HaloOAuth2AuthenticationWebFilter(Oauth2LoginConfiguration configuration,
        ServerSecurityContextRepository securityContextRepository) {
        var authManager = new OAuth2LoginReactiveAuthenticationManager(
            new WebClientReactiveAuthorizationCodeTokenResponseClient(),
            new DefaultReactiveOAuth2UserService()
        );
        var filter = new OAuth2LoginAuthenticationWebFilter(authManager,
            configuration.getAuthorizedClientRepository());
        filter.setRequiresAuthenticationMatcher(configuration.getAuthenticationMatcher());
        var converter = new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(
            configuration.getClientRegistrationRepository()
        );
        var successHandler = new RedirectServerAuthenticationSuccessHandler("/uc");
        successHandler.setRequestCache(configuration.getRequestCache());
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(
            new RedirectServerAuthenticationFailureHandler("/login?oauth2_error")
        );
        filter.setServerAuthenticationConverter(converter);
        filter.setSecurityContextRepository(securityContextRepository);

        this.delegate = filter;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return delegate.filter(exchange, chain);
    }

}
