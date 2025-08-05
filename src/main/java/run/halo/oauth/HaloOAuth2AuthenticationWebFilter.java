package run.halo.oauth;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import io.netty.channel.ChannelOption;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.authentication.ReactiveOidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationCodeAuthenticationTokenConverter;
import org.springframework.security.oauth2.client.web.server.authentication.OAuth2LoginAuthenticationWebFilter;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.netty.transport.ProxyProvider;
import run.halo.app.security.AuthenticationSecurityWebFilter;

/**
 * OAuth2 authentication web filter.
 *
 * @author johnniang
 * @since 2.20.0
 */
@Slf4j
@Component
public class HaloOAuth2AuthenticationWebFilter implements AuthenticationSecurityWebFilter {

    private final WebFilter delegate;

    public HaloOAuth2AuthenticationWebFilter(Oauth2LoginConfiguration configuration,
        ServerSecurityContextRepository securityContextRepository,
        OAuth2Properties oAuth2Properties) {

        var proxy = oAuth2Properties.getProxy();
        var client = HttpClient.create()
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 15_000);
        if (proxy.isEnabled()) {
            client = client.proxy(typeSpec -> {
                    var builder = typeSpec.type(ProxyProvider.Proxy.HTTP)
                        .host(proxy.getHost())
                        .port(proxy.getPort());
                    if (StringUtils.hasText(proxy.getUsername())) {
                        builder.username(proxy.getUsername())
                            .password(u -> proxy.getPassword());
                    }
                    if (proxy.getConnectTimeoutMillis() != null
                        && proxy.getConnectTimeoutMillis() > 0) {
                        builder.connectTimeoutMillis(proxy.getConnectTimeoutMillis());
                    }
                }
            );
        }
        var webClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(client))
            .build();

        var accessTokenResponseClient = new WebClientReactiveAuthorizationCodeTokenResponseClient();
        accessTokenResponseClient.setWebClient(webClient);

        var oauth2AuthManager = new OAuth2LoginReactiveAuthenticationManager(
            accessTokenResponseClient,
            new DefaultReactiveOAuth2UserService()
        );
        var oidcAuthManager = new OidcAuthorizationCodeReactiveAuthenticationManager(
            accessTokenResponseClient,
            new OidcReactiveOAuth2UserService()
        );
        var oidcIdTokenDecodeFactory = new ReactiveOidcIdTokenDecoderFactory();
        oidcIdTokenDecodeFactory.setJwsAlgorithmResolver(clientRegistration -> {
            var configurationMetadata = clientRegistration.getProviderDetails()
                .getConfigurationMetadata();
            try {
                var supportedJwsAlgorithms = JSONObjectUtils.getStringList(
                    new JSONObject(configurationMetadata),
                    "id_token_signing_alg_values_supported"
                );
                // we choose the first one as JWS algorithm
                if (!supportedJwsAlgorithms.isEmpty()) {
                    var jwsAlgorithm = supportedJwsAlgorithms.get(0);
                    return SignatureAlgorithm.from(jwsAlgorithm);
                }
            } catch (ParseException e) {
                // ignore the error.
            }
            // default algorithm
            return SignatureAlgorithm.RS256;
        });
        oidcAuthManager.setJwtDecoderFactory(oidcIdTokenDecodeFactory);
        var authManager =
            new DelegatingReactiveAuthenticationManager(oauth2AuthManager, oidcAuthManager);
        var filter = new OAuth2LoginAuthenticationWebFilter(
            authManager, configuration.getAuthorizedClientRepository()
        );
        filter.setRequiresAuthenticationMatcher(configuration.getAuthenticationMatcher());
        var converter = new ServerOAuth2AuthorizationCodeAuthenticationTokenConverter(
            configuration.getClientRegistrationRepository()
        );
        var successHandler = new RedirectServerAuthenticationSuccessHandler("/uc");
        successHandler.setRequestCache(configuration.getRequestCache());
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(
            new RedirectServerAuthenticationFailureHandler("/login?oauth2_error") {
                @Override
                public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange,
                    AuthenticationException exception) {
                    log.error("Failed to authentication with OAuth2", exception);
                    return super.onAuthenticationFailure(webFilterExchange, exception);
                }
            }
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
