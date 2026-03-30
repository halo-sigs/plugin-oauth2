package run.halo.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import run.halo.app.core.extension.AuthProvider;
import run.halo.app.extension.ConfigMap;
import run.halo.app.extension.Metadata;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.infra.ExternalUrlSupplier;
import run.halo.app.infra.SystemSetting;

/**
 * @author guqing
 * @since 2.0.0
 */
@ExtendWith(MockitoExtension.class)
class OauthClientRegistrationRepositoryTest {

    @Mock
    private ReactiveExtensionClient client;

    @Mock
    ExternalUrlSupplier externalUrlSupplier;

    @InjectMocks
    private OauthClientRegistrationRepository repository;

    @Test
    void findByRegistrationId_withValidId_returnsClientRegistration() throws MalformedURLException {
        AuthProvider authProvider = new AuthProvider();
        authProvider.setMetadata(new Metadata());
        authProvider.getMetadata().setName("github");
        authProvider.setSpec(new AuthProvider.AuthProviderSpec());
        authProvider.getSpec().setDisplayName("GitHub");
        authProvider.getSpec().setAuthenticationUrl("/oauth2/authorization/github");
        authProvider.getSpec().setSettingRef(new AuthProvider.SettingRef());
        authProvider.getSpec().getSettingRef().setName("oauth-github-setting");
        authProvider.getSpec().getSettingRef().setGroup("github");
        authProvider.getSpec().setConfigMapRef(new AuthProvider.ConfigMapRef());
        authProvider.getSpec().getConfigMapRef().setName("oauth-github-config");

        when(client.fetch(eq(AuthProvider.class), eq("github")))
            .thenReturn(Mono.just(authProvider));
        ConfigMap systemConfig = new ConfigMap();
        systemConfig.setData(Map.of(SystemSetting.AuthProvider.GROUP,
            """
                {"states":[{"name":"github", "enabled":true}]}\
                """));
        when(client.fetch(eq(ConfigMap.class), eq(SystemSetting.SYSTEM_CONFIG)))
            .thenReturn(Mono.just(systemConfig));

        Oauth2ClientRegistration registration = new Oauth2ClientRegistration();
        registration.setMetadata(new Metadata());
        registration.getMetadata().setName("github");
        registration.setSpec(new Oauth2ClientRegistration.Oauth2ClientRegistrationSpec());
        registration.getSpec().setAuthorizationUri("fake-uri");
        registration.getSpec().setTokenUri("fake-token-uri");
        when(client.fetch(eq(Oauth2ClientRegistration.class), eq("github")))
            .thenReturn(Mono.just(registration));

        ConfigMap configMap = new ConfigMap();
        configMap.setData(Map.of("github",
            "{\"clientId\":\"my-client-id\",\"clientSecret\":\"my-client-secret\"}"));
        when(client.fetch(eq(ConfigMap.class), eq("oauth-github-config")))
            .thenReturn(Mono.just(configMap));

        StepVerifier.create(repository.findByRegistrationId("github"))
            .assertNext(clientRegistration -> {
                assertThat(clientRegistration.getRegistrationId()).isEqualTo("github");
                assertThat(clientRegistration.getClientId()).isEqualTo("my-client-id");
                assertThat(clientRegistration.getClientSecret()).isEqualTo("my-client-secret");
                assertThat(clientRegistration.getRedirectUri()).isEqualTo(
                    "{baseUrl}/{action}/oauth2/code/{registrationId}"
                );
            })
            .expectComplete()
            .verify();

        when(externalUrlSupplier.getRaw()).thenReturn(new URL("https://www.halo.run/"));

        StepVerifier.create(repository.findByRegistrationId("github"))
            .assertNext(clientRegistration -> {
                assertThat(clientRegistration.getRedirectUri()).isEqualTo(
                    "https://www.halo.run/{action}/oauth2/code/{registrationId}"
                );
            })
            .expectComplete()
            .verify();
    }

    @Test
    void findByRegistrationId_withUnsupportedProvider_throwsProviderNotFoundException() {
        when(client.fetch(eq(AuthProvider.class), eq("unsupported-provider")))
            .thenReturn(Mono.empty());
        assertThatThrownBy(() -> repository.findByRegistrationId("unsupported-provider").block())
            .isInstanceOf(ProviderNotFoundException.class)
            .hasMessage("Unsupported OAuth2 provider: unsupported-provider");
    }

    @Test
    void findByRegistrationId_withSsoProvider_keepsExistingCustomOidcBehavior() {
        AuthProvider authProvider = new AuthProvider();
        authProvider.setMetadata(new Metadata());
        authProvider.getMetadata().setName("sso");
        authProvider.setSpec(new AuthProvider.AuthProviderSpec());
        authProvider.getSpec().setDisplayName("SSO");
        authProvider.getSpec().setAuthenticationUrl("/oauth2/authorization/sso");
        authProvider.getSpec().setSettingRef(new AuthProvider.SettingRef());
        authProvider.getSpec().getSettingRef().setName("sso-oauth2-setting");
        authProvider.getSpec().getSettingRef().setGroup("ssoOauth");
        authProvider.getSpec().setConfigMapRef(new AuthProvider.ConfigMapRef());
        authProvider.getSpec().getConfigMapRef().setName("oauth2-sso-config");

        when(client.fetch(eq(AuthProvider.class), eq("sso")))
            .thenReturn(Mono.just(authProvider));

        ConfigMap systemConfig = new ConfigMap();
        systemConfig.setData(Map.of(SystemSetting.AuthProvider.GROUP,
            """
                {"states":[{"name":"sso", "enabled":true}]}\
                """));
        when(client.fetch(eq(ConfigMap.class), eq(SystemSetting.SYSTEM_CONFIG)))
            .thenReturn(Mono.just(systemConfig));

        Oauth2ClientRegistration registration = new Oauth2ClientRegistration();
        registration.setMetadata(new Metadata());
        registration.getMetadata().setName("sso");
        registration.setSpec(new Oauth2ClientRegistration.Oauth2ClientRegistrationSpec());
        registration.getSpec().setAuthorizationUri("https://example.com/login/oauth/authorize");
        registration.getSpec().setTokenUri("https://example.com/api/login/oauth/access_token");
        registration.getSpec().setUserInfoUri("https://example.com/api/user");
        registration.getSpec().setUserNameAttributeName("name");
        when(client.fetch(eq(Oauth2ClientRegistration.class), eq("sso")))
            .thenReturn(Mono.just(registration));

        ConfigMap configMap = new ConfigMap();
        configMap.setData(Map.of("ssoOauth",
            """
                {
                  "clientId":"sso-client-id",
                  "clientSecret":"sso-client-secret",
                  "authorizationUrl":"https://sso.example.com/oauth2/authorize",
                  "tokenUrl":"https://sso.example.com/oauth2/token",
                  "userInfoUrl":"https://sso.example.com/oauth2/userinfo",
                  "scopes":"openid profile",
                  "userNameAttribute":"preferred_username",
                  "issuerUri":"https://sso.example.com",
                  "jwkSetUri":"https://sso.example.com/oauth2/jwks"
                }\
                """));
        when(client.fetch(eq(ConfigMap.class), eq("oauth2-sso-config")))
            .thenReturn(Mono.just(configMap));

        StepVerifier.create(repository.findByRegistrationId("sso"))
            .assertNext(clientRegistration -> {
                assertThat(clientRegistration.getRegistrationId()).isEqualTo("sso");
                assertThat(clientRegistration.getClientId()).isEqualTo("sso-client-id");
                assertThat(clientRegistration.getClientSecret()).isEqualTo("sso-client-secret");
                assertThat(clientRegistration.getProviderDetails().getAuthorizationUri())
                    .isEqualTo("https://sso.example.com/oauth2/authorize");
                assertThat(clientRegistration.getProviderDetails().getTokenUri())
                    .isEqualTo("https://sso.example.com/oauth2/token");
                assertThat(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri())
                    .isEqualTo("https://sso.example.com/oauth2/userinfo");
                assertThat(clientRegistration.getProviderDetails().getIssuerUri())
                    .isEqualTo("https://sso.example.com");
                assertThat(clientRegistration.getProviderDetails().getJwkSetUri())
                    .isEqualTo("https://sso.example.com/oauth2/jwks");
                assertThat(clientRegistration.getScopes())
                    .containsExactlyInAnyOrder("openid", "profile");
            })
            .expectComplete()
            .verify();
    }

    @Test
    void findByRegistrationId_withLogtoProvider_usesConfiguredOidcEndpoints() {
        AuthProvider authProvider = new AuthProvider();
        authProvider.setMetadata(new Metadata());
        authProvider.getMetadata().setName("logto");
        authProvider.setSpec(new AuthProvider.AuthProviderSpec());
        authProvider.getSpec().setDisplayName("Logto");
        authProvider.getSpec().setAuthenticationUrl("/oauth2/authorization/logto");
        authProvider.getSpec().setSettingRef(new AuthProvider.SettingRef());
        authProvider.getSpec().getSettingRef().setName("logto-oauth2-setting");
        authProvider.getSpec().getSettingRef().setGroup("logtoOauth");
        authProvider.getSpec().setConfigMapRef(new AuthProvider.ConfigMapRef());
        authProvider.getSpec().getConfigMapRef().setName("oauth2-logto-config");

        when(client.fetch(eq(AuthProvider.class), eq("logto")))
            .thenReturn(Mono.just(authProvider));

        ConfigMap systemConfig = new ConfigMap();
        systemConfig.setData(Map.of(SystemSetting.AuthProvider.GROUP,
            """
                {"states":[{"name":"logto", "enabled":true}]}\
                """));
        when(client.fetch(eq(ConfigMap.class), eq(SystemSetting.SYSTEM_CONFIG)))
            .thenReturn(Mono.just(systemConfig));

        Oauth2ClientRegistration registration = new Oauth2ClientRegistration();
        registration.setMetadata(new Metadata());
        registration.getMetadata().setName("logto");
        registration.setSpec(new Oauth2ClientRegistration.Oauth2ClientRegistrationSpec());
        registration.getSpec().setAuthorizationUri("https://example.logto.app/oidc/auth");
        registration.getSpec().setTokenUri("https://example.logto.app/oidc/token");
        registration.getSpec().setUserInfoUri("https://example.logto.app/oidc/me");
        registration.getSpec().setUserNameAttributeName("sub");
        registration.getSpec().setScopes(Set.of("openid", "profile", "email"));
        registration.getSpec().setJwsAlgorithm("ES384");
        when(client.fetch(eq(Oauth2ClientRegistration.class), eq("logto")))
            .thenReturn(Mono.just(registration));

        ConfigMap configMap = new ConfigMap();
        configMap.setData(Map.of("logtoOauth",
            """
                {
                  "clientId":"logto-client-id",
                  "clientSecret":"logto-client-secret",
                  "endpoint":"https://auth.example.com"
                }\
                """));
        when(client.fetch(eq(ConfigMap.class), eq("oauth2-logto-config")))
            .thenReturn(Mono.just(configMap));

        StepVerifier.create(repository.findByRegistrationId("logto"))
            .assertNext(clientRegistration -> {
                assertThat(clientRegistration.getRegistrationId()).isEqualTo("logto");
                assertThat(clientRegistration.getClientId()).isEqualTo("logto-client-id");
                assertThat(clientRegistration.getClientSecret()).isEqualTo("logto-client-secret");
                assertThat(clientRegistration.getProviderDetails().getAuthorizationUri())
                    .isEqualTo("https://auth.example.com/oidc/auth");
                assertThat(clientRegistration.getProviderDetails().getTokenUri())
                    .isEqualTo("https://auth.example.com/oidc/token");
                assertThat(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri())
                    .isEqualTo("https://auth.example.com/oidc/me");
                assertThat(clientRegistration.getProviderDetails().getIssuerUri())
                    .isEqualTo("https://auth.example.com/oidc");
                assertThat(clientRegistration.getProviderDetails().getJwkSetUri())
                    .isEqualTo("https://auth.example.com/oidc/jwks");
                assertThat(clientRegistration.getProviderDetails().getConfigurationMetadata())
                    .containsEntry("jwsAlgorithm", "ES384");
                assertThat(clientRegistration.getScopes())
                    .containsExactlyInAnyOrder("openid", "profile", "email");
            })
            .expectComplete()
            .verify();
    }

    @Test
    void findByRegistrationId_withLogtoIssuerEndpoint_shouldNotDuplicateOidcSegment() {
        AuthProvider authProvider = new AuthProvider();
        authProvider.setMetadata(new Metadata());
        authProvider.getMetadata().setName("logto");
        authProvider.setSpec(new AuthProvider.AuthProviderSpec());
        authProvider.getSpec().setSettingRef(new AuthProvider.SettingRef());
        authProvider.getSpec().getSettingRef().setName("logto-oauth2-setting");
        authProvider.getSpec().getSettingRef().setGroup("logtoOauth");
        authProvider.getSpec().setConfigMapRef(new AuthProvider.ConfigMapRef());
        authProvider.getSpec().getConfigMapRef().setName("oauth2-logto-config");

        when(client.fetch(eq(AuthProvider.class), eq("logto")))
            .thenReturn(Mono.just(authProvider));

        ConfigMap systemConfig = new ConfigMap();
        systemConfig.setData(Map.of(SystemSetting.AuthProvider.GROUP,
            """
                {"states":[{"name":"logto", "enabled":true}]}\
                """));
        when(client.fetch(eq(ConfigMap.class), eq(SystemSetting.SYSTEM_CONFIG)))
            .thenReturn(Mono.just(systemConfig));

        Oauth2ClientRegistration registration = new Oauth2ClientRegistration();
        registration.setMetadata(new Metadata());
        registration.getMetadata().setName("logto");
        registration.setSpec(new Oauth2ClientRegistration.Oauth2ClientRegistrationSpec());
        registration.getSpec().setAuthorizationUri("https://example.logto.app/oidc/auth");
        registration.getSpec().setTokenUri("https://example.logto.app/oidc/token");
        registration.getSpec().setUserInfoUri("https://example.logto.app/oidc/me");
        registration.getSpec().setUserNameAttributeName("sub");
        registration.getSpec().setScopes(Set.of("openid", "profile", "email"));
        registration.getSpec().setJwsAlgorithm("ES384");
        when(client.fetch(eq(Oauth2ClientRegistration.class), eq("logto")))
            .thenReturn(Mono.just(registration));

        ConfigMap configMap = new ConfigMap();
        configMap.setData(Map.of("logtoOauth",
            """
                {
                  "clientId":"logto-client-id",
                  "clientSecret":"logto-client-secret",
                  "endpoint":"https://auth.example.com/oidc/"
                }\
                """));
        when(client.fetch(eq(ConfigMap.class), eq("oauth2-logto-config")))
            .thenReturn(Mono.just(configMap));

        StepVerifier.create(repository.findByRegistrationId("logto"))
            .assertNext(clientRegistration -> {
                assertThat(clientRegistration.getProviderDetails().getIssuerUri())
                    .isEqualTo("https://auth.example.com/oidc");
                assertThat(clientRegistration.getProviderDetails().getAuthorizationUri())
                    .isEqualTo("https://auth.example.com/oidc/auth");
            })
            .expectComplete()
            .verify();
    }
}
