package run.halo.oauth;

import static org.apache.commons.lang3.StringUtils.defaultString;
import static run.halo.oauth.SocialServerOauth2AuthorizationRequestResolver.SOCIAL_CONNECTION;

import java.nio.charset.StandardCharsets;
import org.apache.commons.lang3.StringUtils;
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
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriUtils;
import reactor.core.publisher.Mono;
import run.halo.app.infra.exception.AccessDeniedException;
import run.halo.app.security.AdditionalWebFilter;

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
        authenticationFilter.setAuthenticationSuccessHandler(
            oauth2LoginConfiguration.getAuthenticationSuccessHandler());
        authenticationFilter.setAuthenticationFailureHandler(
            oauth2LoginConfiguration.getAuthenticationFailureHandler());
        authenticationFilter.setSecurityContextRepository(this.securityContextRepository);
        return authenticationFilter;
    }

    class SocialLoginAuthenticationWebFilter extends OAuth2LoginAuthenticationWebFilter {

        private ServerAuthenticationSuccessHandler authenticationSuccessHandler;
        private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

        /**
         * Creates an instance.
         *
         * @param authenticationManager      the authentication manager to use
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
                    String redirectUri = (String) additionalParameters.get("binding_redirect_uri");
                    if (Boolean.parseBoolean(socialConnection)) {
                        // Social connect successfully, finish the process
                        return createConnection(webFilterExchange, authenticationResult)
                            .then(bindSuccessHandler(redirectUri)
                                .onAuthenticationSuccess(webFilterExchange, authentication)
                            );
                    }
                    return userConnectionService.isConnected(registrationId,
                            authenticationResult.getName())
                        .flatMap(connected -> {
                            if (connected) {
                                // login
                                return mappedToSystemUserAuthentication(registrationId,
                                    authenticationResult)
                                    .flatMap(result -> handleAuthenticationSuccess(result,
                                        webFilterExchange));
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
            String loginName = oauth2User.getName();
            String name = defaultString(oauth2User.getAttribute("name"), loginName);
            String redirectUri = String.format("/console#/binding/%s?login=%s&name=%s",
                registrationId, loginName, name);
            String encodedUri = UriUtils.encodePath(redirectUri, StandardCharsets.UTF_8);
            return new RedirectServerAuthenticationSuccessHandler(encodedUri);
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

        private ServerAuthenticationSuccessHandler bindSuccessHandler(String redirectUri) {
            if (StringUtils.isBlank(redirectUri)) {
                return new RedirectServerAuthenticationSuccessHandler("/console#/dashboard");
            }
            return new RedirectServerAuthenticationSuccessHandler(redirectUri);
        }

        @Override
        public void setAuthenticationSuccessHandler(
            ServerAuthenticationSuccessHandler authenticationSuccessHandler) {
            super.setAuthenticationSuccessHandler(authenticationSuccessHandler);
            this.authenticationSuccessHandler = authenticationSuccessHandler;
        }

        Mono<Void> handleAuthenticationSuccess(Authentication authentication,
                                               WebFilterExchange webFilterExchange) {
            // Save the authentication result in the SecurityContext
            ServerWebExchange exchange = webFilterExchange.getExchange();
            SecurityContextImpl securityContext = new SecurityContextImpl();
            securityContext.setAuthentication(authentication);
            return securityContextRepository.save(exchange, securityContext)
                .then(this.authenticationSuccessHandler.onAuthenticationSuccess(webFilterExchange,
                    authentication))
                .contextWrite(
                    ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));
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
