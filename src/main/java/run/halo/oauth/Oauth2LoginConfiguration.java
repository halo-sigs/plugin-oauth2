package run.halo.oauth;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REGISTRATION_ID;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.infra.ExternalUrlSupplier;
import run.halo.app.security.LoginHandlerEnhancer;

/**
 * Oauth2 login configuration.
 *
 * @author guqing
 * @since 1.0.0
 */
@Slf4j
@Getter
@Configuration
@EnableAsync
public class Oauth2LoginConfiguration {
    private final ServerWebExchangeMatcher authenticationMatcher;
    private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
    private final ReactiveClientRegistrationRepository clientRegistrationRepository;
    private final ReactiveOAuth2AuthorizedClientService authorizedClientService;

    private final ReactiveExtensionClient extensionClient;

    private final LoginHandlerEnhancer loginHandlerEnhancer;

    private final ExternalUrlSupplier externalUrlSupplier;

    private ServerRequestCache requestCache = new WebSessionServerRequestCache();

    public Oauth2LoginConfiguration(ReactiveExtensionClient extensionClient,
        LoginHandlerEnhancer loginHandlerEnhancer,
        ExternalUrlSupplier externalUrlSupplier) {
        this.extensionClient = extensionClient;
        this.loginHandlerEnhancer = loginHandlerEnhancer;
        this.externalUrlSupplier = externalUrlSupplier;

        Initializer initializer = new Initializer();
        this.authenticationMatcher = initializer.getAuthenticationMatcher();
        this.authorizedClientRepository = initializer.getAuthorizedClientRepository();
        this.clientRegistrationRepository = initializer.getClientRegistrationRepository();
        this.authorizedClientService = initializer.getAuthorizedClientService();
    }

    @Autowired(required = false)
    public void setRequestCache(ServerRequestCache requestCache) {
        this.requestCache = requestCache;
    }

    class Initializer {

        ServerWebExchangeMatcher getAuthenticationMatcher() {
            return createAttemptAuthenticationRequestMatcher();
        }

        ServerWebExchangeMatcher createAttemptAuthenticationRequestMatcher() {
            return new PathPatternParserServerWebExchangeMatcher(
                "/login/oauth2/code/{" + REGISTRATION_ID + "}");
        }

        ReactiveClientRegistrationRepository getClientRegistrationRepository() {
            return new OauthClientRegistrationRepository(extensionClient, externalUrlSupplier);
        }

        ServerOAuth2AuthorizedClientRepository getAuthorizedClientRepository() {
            ReactiveOAuth2AuthorizedClientService authorizedClientService =
                getAuthorizedClientService();
            return new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(
                authorizedClientService);
        }

        ReactiveOAuth2AuthorizedClientService getAuthorizedClientService() {
            return new DefaultOAuth2AuthorizedClientService(extensionClient,
                getClientRegistrationRepository());
        }
    }
}
