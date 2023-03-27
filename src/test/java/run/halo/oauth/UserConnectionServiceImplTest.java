package run.halo.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.UserConnection;
import run.halo.app.extension.Metadata;
import run.halo.app.extension.ReactiveExtensionClient;

/**
 * @author guqing
 * @since 2.0.0
 */
@ExtendWith(MockitoExtension.class)
class UserConnectionServiceImplTest {

    @Mock
    private ReactiveExtensionClient client;

    @Mock
    private Oauth2UserProfileMapperManager mapperManager;

    @InjectMocks
    private UserConnectionServiceImpl service;

    @Test
    public void testCreateConnection() {
        Map<String, Object> attributes = Map.of("id", "testuser", "name", "Test User", "avatar_url",
            "http://test.com/avatar.png",
            "html_url", "http://test.com/profile");
        DefaultOAuth2User oauth2User =
            new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("read:user")), attributes,
                "id");
        // mock OAuth2LoginAuthenticationToken
        String tokenValue = "testtoken";
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER, tokenValue, Instant.now(),
            Instant.now().plusSeconds(3600));
        OAuth2RefreshToken refreshToken =
            new OAuth2RefreshToken("testrefresh", Instant.now().plusSeconds(30));

        ClientRegistration clientRegistration = CommonOAuth2Provider.GITHUB.getBuilder("github")
            .clientId("fake-client-id")
            .clientSecret("fake-client-secret")
            .build();
        OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri("/oauth2/authorization/github")
            .clientId(clientRegistration.getClientId())
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .build();
        OAuth2AuthorizationResponse response = OAuth2AuthorizationResponse.success("code")
            .redirectUri("http://localhost:8080/login/oauth2/code/github")
            .build();
        OAuth2AuthorizationExchange exchange =
            new OAuth2AuthorizationExchange(request, response);
        OAuth2LoginAuthenticationToken authentication = new OAuth2LoginAuthenticationToken(
            clientRegistration, exchange, oauth2User,
            List.of(new SimpleGrantedAuthority("read:user")),
            accessToken);

        // mock UserConnection
        UserConnection expectedConnection = new UserConnection();
        expectedConnection.setMetadata(new Metadata());
        expectedConnection.getMetadata().setGenerateName("connection-");
        expectedConnection.getMetadata().setName("");

        UserConnection.UserConnectionSpec spec = new UserConnection.UserConnectionSpec();
        expectedConnection.setSpec(spec);
        String username = "testuser";
        spec.setUsername(username);
        spec.setProviderUserId(oauth2User.getName());
        String registrationId = "testreg";
        spec.setRegistrationId(registrationId);
        spec.setAccessToken(tokenValue);
        spec.setExpiresAt(accessToken.getExpiresAt());
        spec.setRefreshToken(refreshToken.getTokenValue());

        Oauth2UserProfile userProfile = Oauth2UserProfile.builder()
            .displayName("Test User")
            .avatarUrl("http://test.com/avatar.png")
            .profileUrl("http://test.com/profile")
            .username("testuser")
            .build();


        when(mapperManager.mapProfile(any(), any())).thenReturn(userProfile);

        // mock client
        when(client.list(eq(UserConnection.class), any(), eq(null))).thenReturn(Flux.empty());
        when(client.create(any())).thenReturn(Mono.just(expectedConnection));

        // test createConnection
        UserConnection result = service.createConnection(username, authentication).block();
        assertNotNull(result);
        assertEquals(expectedConnection, result);
        verify(client, times(1)).create(any());
    }
}
