package run.halo.oauth;

import static org.apache.commons.lang3.StringUtils.defaultString;
import static run.halo.oauth.SocialServerOauth2AuthorizationRequestResolver.SOCIAL_CONNECTION;

import java.net.URI;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.authentication.OAuth2LoginAuthenticationWebFilter;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;
import reactor.core.publisher.Mono;
import run.halo.app.security.AdditionalWebFilter;
import run.halo.app.security.LoginHandlerEnhancer;

/**
 * Oauth2 authenticator.
 *
 * @author guqing
 * @since 1.0.0
 */
@Component
public class Oauth2Authenticator implements AdditionalWebFilter {
    private final Oauth2LoginConfiguration oauth2LoginConfiguration;
    private final ServerSecurityContextRepository securityContextRepository;
    private final AuthenticationWebFilter authenticationWebFilter;
    private final SocialUserDetailsService socialUserDetailsService;
    private final UserConnectionService userConnectionService;

    public Oauth2Authenticator(Oauth2LoginConfiguration oauth2LoginConfiguration,
        ServerSecurityContextRepository securityContextRepository,
        SocialUserDetailsService socialUserDetailsService,
        UserConnectionService userConnectionService) {
        this.oauth2LoginConfiguration = oauth2LoginConfiguration;
        this.securityContextRepository = securityContextRepository;
        this.socialUserDetailsService = socialUserDetailsService;
        this.userConnectionService = userConnectionService;

        this.authenticationWebFilter = createAuthenticationWebFilter();
    }

    @Override
    @NonNull
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
        return authenticationWebFilter.filter(exchange, chain);
    }

    @Override
    public int getOrder() {
        return SecurityWebFiltersOrder.AUTHENTICATION.getOrder();
    }

    AuthenticationWebFilter createAuthenticationWebFilter() {
        ReactiveAuthenticationManager manager = oauth2LoginConfiguration.getAuthenticationManager();

        ServerOAuth2AuthorizedClientRepository authorizedClientRepository =
            oauth2LoginConfiguration.getAuthorizedClientRepository();

        AuthenticationWebFilter authenticationFilter =
            new SocialLoginAuthenticationWebFilter(manager,
                authorizedClientRepository);
        authenticationFilter.setRequiresAuthenticationMatcher(
            oauth2LoginConfiguration.getAuthenticationMatcher());
        authenticationFilter.setServerAuthenticationConverter(
            oauth2LoginConfiguration.getAuthenticationConverter());
        authenticationFilter.setAuthenticationFailureHandler(
            oauth2LoginConfiguration.getAuthenticationFailureHandler());
        authenticationFilter.setSecurityContextRepository(this.securityContextRepository);
        return authenticationFilter;
    }

    private LoginHandlerEnhancer getLoginHandlerEnhancer() {
        return oauth2LoginConfiguration.getLoginHandlerEnhancer();
    }

    class SocialLoginAuthenticationWebFilter extends OAuth2LoginAuthenticationWebFilter {

        private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();
        private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

        /**
         * Creates an instance.
         *
         * @param authenticationManager the authentication manager to use
         * @param authorizedClientRepository optional authorized client repository to use
         */
        public SocialLoginAuthenticationWebFilter(
            ReactiveAuthenticationManager authenticationManager,
            ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
            super(authenticationManager, authorizedClientRepository);

            Assert.notNull(authorizedClientRepository, "authorizedClientService cannot be null");
            this.authorizedClientRepository = authorizedClientRepository;
        }

        @Override
        protected Mono<Void> onAuthenticationSuccess(Authentication authentication,
            WebFilterExchange webFilterExchange) {
            OAuth2LoginAuthenticationToken authenticationResult =
                (OAuth2LoginAuthenticationToken) authentication;
            OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                authenticationResult.getClientRegistration(), authenticationResult.getName(),
                authenticationResult.getAccessToken(), authenticationResult.getRefreshToken());
            String registrationId = authorizedClient.getClientRegistration().getRegistrationId();

            return this.authorizedClientRepository
                .saveAuthorizedClient(authorizedClient, authenticationResult,
                    webFilterExchange.getExchange())
                .then(Mono.defer(() -> {
                    var additionalParameters = authenticationResult.getAuthorizationExchange()
                        .getAuthorizationRequest()
                        .getAdditionalParameters();
                    String socialConnection = (String) additionalParameters.get(SOCIAL_CONNECTION);
                    String bindingRedirectUri =
                        (String) additionalParameters.get("binding_redirect_uri");
                    String loginRedirectUri =
                        (String) additionalParameters.get("login_redirect_uri");
                    if (Boolean.parseBoolean(socialConnection)) {
                        // Social connect successfully, finish the process
                        return createConnection(webFilterExchange, authenticationResult)
                            .then(handleBindSuccessHandler(webFilterExchange, bindingRedirectUri));
                    }
                    return userConnectionService.isConnected(registrationId,
                            authenticationResult.getName())
                        .flatMap(connected -> {
                            if (connected) {
                                // login
                                return mappedToSystemUserAuthentication(registrationId,
                                    authenticationResult)
                                    .flatMap(result -> handleAuthenticationSuccess(result,
                                        webFilterExchange, loginRedirectUri));
                            }
                            // signup
                            OAuth2User principal = authenticationResult.getPrincipal();
                            return registrationPageHandler(registrationId, principal)
                                .onAuthenticationSuccess(webFilterExchange, authentication);
                        });
                }));
        }

        private ServerAuthenticationSuccessHandler registrationPageHandler(String registrationId,
            OAuth2User oauth2User) {
            Assert.notNull(registrationId, "registrationId cannot be null");
            Assert.notNull(oauth2User, "oauth2User cannot be null");

            String loginName = oauth2User.getName();
            String name = defaultString(oauth2User.getAttribute("name"), loginName);
            MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
            queryParams.add("login", loginName);
            queryParams.add("name", name);

            String redirectUri = UriComponentsBuilder.fromPath("/console/binding/{registrationId}")
                .uriVariables(Map.of("registrationId", registrationId))
                .queryParams(UriUtils.encodeQueryParams(queryParams))
                .build()
                .toUriString();
            return new RedirectServerAuthenticationSuccessHandler(redirectUri);
        }

        private Mono<Void> createConnection(WebFilterExchange webFilterExchange,
            OAuth2LoginAuthenticationToken authenticationToken) {
            return securityContextRepository.load(webFilterExchange.getExchange())
                .map(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated)
                .switchIfEmpty(Mono.error(new AccessDeniedException(
                    "Binding cannot be completed without user authentication")))
                .flatMap(authentication -> userConnectionService
                    .createConnection(authentication.getName(), authenticationToken)
                )
                .then();
        }

        private Mono<Void> handleBindSuccessHandler(WebFilterExchange webFilterExchange,
            String redirectUri) {
            return getRedirectUri(webFilterExchange.getExchange(), redirectUri)
                .defaultIfEmpty(URI.create("/console"))
                .flatMap(
                    uri -> redirectStrategy.sendRedirect(webFilterExchange.getExchange(), uri));
        }

        Mono<Void> handleAuthenticationSuccess(Authentication authentication,
            WebFilterExchange webFilterExchange,
            String redirectUri) {
            // Save the authentication result in the SecurityContext
            ServerWebExchange exchange = webFilterExchange.getExchange();
            SecurityContextImpl securityContext = new SecurityContextImpl();
            securityContext.setAuthentication(authentication);
            return securityContextRepository.save(exchange, securityContext)
                .then(authenticationSuccessRedirection(webFilterExchange,
                    redirectUri)
                )
                .contextWrite(
                    ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)))
                .then(getLoginHandlerEnhancer().onLoginSuccess(exchange, authentication));
        }

        Mono<Void> authenticationSuccessRedirection(WebFilterExchange webFilterExchange,
            String redirectUri) {
            return getRedirectUri(webFilterExchange.getExchange(), redirectUri)
                .defaultIfEmpty(URI.create("/console"))
                .flatMap(uri ->
                    this.redirectStrategy.sendRedirect(webFilterExchange.getExchange(), uri)
                )
                .then();
        }

        Mono<URI> getRedirectUri(ServerWebExchange exchange, String redirectUriString) {
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

        Mono<Authentication> mappedToSystemUserAuthentication(String registrationId,
            Authentication authentication) {
            return socialUserDetailsService.loadUserByUserId(registrationId,
                    authentication.getName())
                .map(userDetails -> UsernamePasswordAuthenticationToken.authenticated(
                    userDetails.getUsername(), userDetails.getPassword(),
                    userDetails.getAuthorities())
                );
        }
    }
}
