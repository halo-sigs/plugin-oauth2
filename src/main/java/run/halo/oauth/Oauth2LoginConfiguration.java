package run.halo.oauth;

import java.net.URI;
import java.util.Optional;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.authentication.ReactiveOidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.OAuth2AuthorizationRequestRedirectWebFilter;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationCodeAuthenticationTokenConverter;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.ClassUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import run.halo.app.extension.ReactiveExtensionClient;

/**
 * Oauth2 login configuration.
 *
 * @author guqing
 * @since 1.0.0
 */
@Getter
@Component
public final class Oauth2LoginConfiguration {
    private final ReactiveAuthenticationManager authenticationManager;
    private final ServerAuthenticationFailureHandler authenticationFailureHandler;
    private final ServerWebExchangeMatcher authenticationMatcher;
    private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
    private final ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest>
        authorizationRequestRepository;
    private final ServerRedirectStrategy authorizationRedirectStrategy;
    private final ServerAuthenticationConverter authenticationConverter;
    private final ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
        accessTokenResponseClient;
    private final ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService;
    private final ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService;
    private final ReactiveClientRegistrationRepository clientRegistrationRepository;
    private final ReactiveOAuth2AuthorizedClientService authorizedClientService;
    private final OAuth2AuthorizationRequestRedirectWebFilter redirectWebFilter;

    private final ReactiveExtensionClient extensionClient;
    private ServerRequestCache requestCache = new WebSessionServerRequestCache();

    public Oauth2LoginConfiguration(ReactiveExtensionClient extensionClient) {
        this.extensionClient = extensionClient;

        Initializer initializer = new Initializer();
        this.authenticationManager = initializer.getAuthenticationManager();
        this.authenticationFailureHandler = initializer.getAuthenticationFailureHandler();
        this.authenticationMatcher = initializer.getAuthenticationMatcher();
        this.authorizedClientRepository = initializer.getAuthorizedClientRepository();
        this.authorizationRequestRepository = initializer.getAuthorizationRequestRepository();
        this.authorizationRedirectStrategy = initializer.getAuthorizationRedirectStrategy();
        this.authenticationConverter =
            initializer.getAuthenticationConverter(initializer.getClientRegistrationRepository());
        this.accessTokenResponseClient = initializer.getAccessTokenResponseClient();
        this.oauth2UserService = initializer.getOauth2UserService();
        this.oidcUserService = initializer.getOidcUserService();
        this.clientRegistrationRepository = initializer.getClientRegistrationRepository();
        this.authorizedClientService = initializer.getAuthorizedClientService();
        this.redirectWebFilter = initializer.getRedirectWebFilter();
    }

    @Autowired(required = false)
    public void setRequestCache(ServerRequestCache requestCache) {
        this.requestCache = requestCache;
    }

    class Initializer {

        ServerAuthenticationFailureHandler getAuthenticationFailureHandler() {
            return new RedirectServerAuthenticationFailureHandler("/console/login?error");
        }

        GrantedAuthoritiesMapper getAuthoritiesMapper() {
            return new SimpleAuthorityMapper();
        }

        ReactiveAuthenticationManager getAuthenticationManager() {
            return createDefaultAuthenticationManager();
        }

        ServerWebExchangeMatcher getAuthenticationMatcher() {
            return createAttemptAuthenticationRequestMatcher();
        }

        ReactiveAuthenticationManager createDefaultAuthenticationManager() {
            ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> client =
                getAccessTokenResponseClient();
            OAuth2LoginReactiveAuthenticationManager oauth2Manager =
                new OAuth2LoginReactiveAuthenticationManager(
                    client, getOauth2UserService());

            GrantedAuthoritiesMapper authoritiesMapper = getAuthoritiesMapper();
            oauth2Manager.setAuthoritiesMapper(authoritiesMapper);

            boolean oidcAuthenticationProviderEnabled = ClassUtils
                .isPresent("org.springframework.security.oauth2.jwt.JwtDecoder",
                    this.getClass().getClassLoader());
            if (!oidcAuthenticationProviderEnabled) {
                return oauth2Manager;
            }
            OidcAuthorizationCodeReactiveAuthenticationManager oidc =
                new OidcAuthorizationCodeReactiveAuthenticationManager(
                    client, getOidcUserService());

            oidc.setJwtDecoderFactory(getReactiveJwtDecoderFactory());

            oidc.setAuthoritiesMapper(authoritiesMapper);
            return new DelegatingReactiveAuthenticationManager(oidc, oauth2Manager);
        }

        ReactiveJwtDecoderFactory<ClientRegistration> getReactiveJwtDecoderFactory() {
            return new ReactiveOidcIdTokenDecoderFactory();
        }

        ServerWebExchangeMatcher createAttemptAuthenticationRequestMatcher() {
            return new PathPatternParserServerWebExchangeMatcher(
                "/login/oauth2/code/{registrationId}");
        }

        ReactiveOAuth2UserService<OidcUserRequest, OidcUser> getOidcUserService() {
            return new OidcReactiveOAuth2UserService();
        }

        ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> getOauth2UserService() {
            return new DefaultReactiveOAuth2UserService();
        }

        ReactiveOAuth2AccessTokenResponseClient
            <OAuth2AuthorizationCodeGrantRequest> getAccessTokenResponseClient() {
            return new WebClientReactiveAuthorizationCodeTokenResponseClient();
        }

        ReactiveClientRegistrationRepository getClientRegistrationRepository() {
            return new OauthClientRegistrationRepository(extensionClient);
        }

        OAuth2AuthorizationRequestRedirectWebFilter getRedirectWebFilter() {
            var requestResolver = new SocialServerOauth2AuthorizationRequestResolver(
                getClientRegistrationRepository());
            return new OAuth2AuthorizationRequestRedirectWebFilter(requestResolver);
        }

        ServerOAuth2AuthorizedClientRepository getAuthorizedClientRepository() {
            ReactiveOAuth2AuthorizedClientService authorizedClientService =
                getAuthorizedClientService();
            return new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(
                authorizedClientService);
        }

        ServerAuthenticationConverter getAuthenticationConverter(
            ReactiveClientRegistrationRepository clientRegistrationRepository) {
            ServerOAuth2AuthorizationCodeAuthenticationTokenConverter delegate =
                new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(
                    clientRegistrationRepository);
            delegate.setAuthorizationRequestRepository(getAuthorizationRequestRepository());
            return (exchange) -> delegate.convert(exchange).onErrorMap(
                OAuth2AuthorizationException.class,
                (e) -> new OAuth2AuthenticationException(e.getError(),
                    e.getError().toString()));
        }

        ServerAuthorizationRequestRepository
            <OAuth2AuthorizationRequest> getAuthorizationRequestRepository() {
            return new WebSessionOAuth2ServerAuthorizationRequestRepository();
        }

        ServerRedirectStrategy getAuthorizationRedirectStrategy() {
            return new DefaultServerRedirectStrategy();
        }

        ReactiveOAuth2AuthorizedClientService getAuthorizedClientService() {
            return new DefaultOAuth2AuthorizedClientService(extensionClient,
                getClientRegistrationRepository());
        }
    }

    static class QueryParamRedirectServerAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {
        private static final String REDIRECT_URI_PARAM = "login_redirect_uri";
        private URI location = URI.create("/");

        private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

        /**
         * Creates a new instance with location of "/"
         */
        public QueryParamRedirectServerAuthenticationSuccessHandler() {
        }

        /**
         * Creates a new instance with the specified location
         * @param location the location to redirect if the no request is cached in
         * {@link #setRequestCache(ServerRequestCache)}
         */
        public QueryParamRedirectServerAuthenticationSuccessHandler(String location) {
            this.location = URI.create(location);
        }

        @Override
        public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange,
                                                  Authentication authentication) {

            return getRedirectUri(webFilterExchange.getExchange(), authentication)
                .defaultIfEmpty(this.location)
                .flatMap(redirectUri ->
                    redirectStrategy.sendRedirect(webFilterExchange.getExchange(), redirectUri)
                );
        }

        Mono<URI> getRedirectUri(ServerWebExchange exchange, Authentication authentication) {
            String redirectUriString = Optional.of(authentication)
                .filter(a -> a instanceof OAuth2LoginAuthenticationToken)
                .map(OAuth2LoginAuthenticationToken.class::cast)
                .map(authenticationResult -> {
                    var additionalParameters = authenticationResult.getAuthorizationExchange()
                        .getAuthorizationRequest()
                        .getAdditionalParameters();
                    return (String) additionalParameters.get(REDIRECT_URI_PARAM);
                })
                .orElse(null);
            ServerHttpRequest request = exchange.getRequest();
            if (StringUtils.isBlank(redirectUriString)) {
                return Mono.empty();
            }
            URI redirectUri = URI.create(redirectUriString);
            // Only redirect to the same host and port
            if (redirectUri.getAuthority() != null
                && !redirectUri.getAuthority().equals(request.getURI().getAuthority())) {
                return Mono.empty();
            }
            return Mono.just(redirectUri);
        }
    }
}
