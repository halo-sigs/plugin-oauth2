package run.halo.oauth;

import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationCodeAuthenticationTokenConverter;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import run.halo.app.core.user.service.UserConnectionService;
import run.halo.app.security.AuthenticationSecurityWebFilter;

@Component
public class HaloOAuth2AuthenticationWebFilter implements AuthenticationSecurityWebFilter {

    private final WebFilter delegate;

    public HaloOAuth2AuthenticationWebFilter(Oauth2LoginConfiguration configuration,
        ServerSecurityContextRepository securityContextRepository,
        UserConnectionService connectionService,
        ReactiveUserDetailsService userDetailsService) {
        var authManager = new OAuth2LoginReactiveAuthenticationManager(
            new WebClientReactiveAuthorizationCodeTokenResponseClient(),
            new DefaultReactiveOAuth2UserService()
        );
        var filter = new HaloOAuth2LoginAuthenticationWebFilter(
            authManager,
            configuration.getAuthorizedClientRepository(),
            connectionService,
            userDetailsService
        );
        filter.setRequiresAuthenticationMatcher(configuration.getAuthenticationMatcher());
        var converter = new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(
            configuration.getClientRegistrationRepository()
        );
        filter.setAuthenticationSuccessHandler(
            new RedirectServerAuthenticationSuccessHandler("/uc")
        );
        filter.setAuthenticationFailureHandler(
            new RedirectServerAuthenticationFailureHandler("/console/login?error")
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
