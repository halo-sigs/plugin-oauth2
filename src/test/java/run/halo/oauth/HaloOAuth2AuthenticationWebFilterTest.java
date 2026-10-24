package run.halo.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.netty.http.server.HttpServer;

class HaloOAuth2AuthenticationWebFilterTest {

    @Test
    void supportsTokenResponseHeadersLargerThan8192Bytes() {
        var server = HttpServer.create()
            .port(0)
            .handle((request, response) -> {
                response.responseHeaders().set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
                if (request.uri().startsWith("/token")) {
                    response.addHeader("X-Large-Header", "x".repeat(9000));
                    return response.sendString(Mono.just("""
                        {"access_token":"test-token","token_type":"bearer","scope":"read:user"}
                        """));
                }
                return response.sendString(Mono.just("""
                    {"id":123,"login":"octocat"}
                    """));
            })
            .bindNow();
        try {
            var baseUri = "http://localhost:" + server.port();
            var registration = ClientRegistration.withRegistrationId("github")
                .clientId("test-client")
                .clientSecret("test-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri(baseUri + "/authorize")
                .tokenUri(baseUri + "/token")
                .userInfoUri(baseUri + "/user")
                .userNameAttributeName("id")
                .scope("read:user")
                .build();

            var configuration = mock(Oauth2LoginConfiguration.class);
            when(configuration.getAuthenticationMatcher()).thenReturn(
                new PathPatternParserServerWebExchangeMatcher("/login/oauth2/code/{registrationId}"));
            when(configuration.getClientRegistrationRepository())
                .thenReturn(registrationId -> Mono.just(registration));
            var authorizedClientRepository = mock(ServerOAuth2AuthorizedClientRepository.class);
            when(authorizedClientRepository.saveAuthorizedClient(any(), any(), any()))
                .thenReturn(Mono.empty());
            when(configuration.getAuthorizedClientRepository()).thenReturn(authorizedClientRepository);
            when(configuration.getRequestCache()).thenReturn(new WebSessionServerRequestCache());
            var securityContextRepository = mock(ServerSecurityContextRepository.class);
            when(securityContextRepository.save(any(), any())).thenReturn(Mono.empty());
            var filter = new HaloOAuth2AuthenticationWebFilter(configuration,
                securityContextRepository, new OAuth2Properties());

            var exchange = MockServerWebExchange.from(MockServerHttpRequest
                .get("/login/oauth2/code/github?code=test-code&state=test-state"));
            var authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(registration.getProviderDetails().getAuthorizationUri())
                .clientId(registration.getClientId())
                .redirectUri("http://localhost/login/oauth2/code/github")
                .state("test-state")
                .attributes(attributes -> attributes.put("registration_id", "github"))
                .build();
            new WebSessionOAuth2ServerAuthorizationRequestRepository()
                .saveAuthorizationRequest(authorizationRequest, exchange)
                .block(Duration.ofSeconds(5));
            var chain = mock(WebFilterChain.class);
            when(chain.filter(any())).thenReturn(Mono.empty());
            filter.filter(exchange, chain).block(Duration.ofSeconds(5));

            assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.LOCATION))
                .isEqualTo("/uc");
        } finally {
            server.disposeNow();
        }
    }
}
