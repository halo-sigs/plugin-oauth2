package run.halo.oauth;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import reactor.core.publisher.Mono;
import run.halo.app.core.user.service.UserConnectionService;
import run.halo.app.security.authentication.oauth2.HaloOAuth2AuthenticationToken;

class HaloOAuth2LoginAuthenticationWebFilter extends AuthenticationWebFilter {

    private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

    private final UserConnectionService connectionService;

    private final ReactiveUserDetailsService userDetailsService;

    private final AuthenticationTrustResolver authenticationTrustResolver =
        new AuthenticationTrustResolverImpl();

    /**
     * Creates an instance
     *
     * @param authenticationManager the authentication manager to use
     * @param authorizedClientRepository
     */
    public HaloOAuth2LoginAuthenticationWebFilter(
        ReactiveAuthenticationManager authenticationManager,
        ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
        UserConnectionService connectionService,
        ReactiveUserDetailsService userDetailsService) {
        super(authenticationManager);
        this.authorizedClientRepository = authorizedClientRepository;
        this.connectionService = connectionService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected Mono<Void> onAuthenticationSuccess(Authentication authentication,
        WebFilterExchange webFilterExchange) {
        OAuth2LoginAuthenticationToken authenticationResult =
            (OAuth2LoginAuthenticationToken) authentication;
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
            authenticationResult.getClientRegistration(), authenticationResult.getName(),
            authenticationResult.getAccessToken(), authenticationResult.getRefreshToken());
        OAuth2AuthenticationToken result =
            new OAuth2AuthenticationToken(authenticationResult.getPrincipal(),
                authenticationResult.getAuthorities(),
                authenticationResult.getClientRegistration().getRegistrationId());
        var registrationId = result.getAuthorizedClientRegistrationId();
        var oauth2User = result.getPrincipal();
        return ReactiveSecurityContextHolder.getContext()
            .map(SecurityContext::getAuthentication)
            .filter(authenticationTrustResolver::isAuthenticated)
            .flatMap(oldToken -> connectionService.getAndUpdateUserConnection(
                    registrationId, oauth2User
                )
                .switchIfEmpty(Mono.defer(() -> connectionService.createUserConnection(
                    oldToken.getName(), registrationId, oauth2User
                ))))
            // not authenticated before
            .switchIfEmpty(Mono.defer(() -> connectionService.getAndUpdateUserConnection(
                registrationId, oauth2User
            )))
            .flatMap(connection -> {
                var username = connection.getSpec().getUsername();
                return userDetailsService.findByUsername(username)
                    .switchIfEmpty(Mono.error(() -> new UsernameNotFoundException(
                        "Username " + username + " not found"
                    )));
            })
            .map(
                userDetails -> HaloOAuth2AuthenticationToken.authenticated(userDetails, result)
            )
            .switchIfEmpty(
                Mono.fromSupplier(() -> HaloOAuth2AuthenticationToken.unauthenticated(result))
            )
            .flatMap(haloAuth -> this.authorizedClientRepository.saveAuthorizedClient(
                        authorizedClient, authenticationResult, webFilterExchange.getExchange()
                    )
                    .then(super.onAuthenticationSuccess(haloAuth, webFilterExchange))
            );
    }
}
