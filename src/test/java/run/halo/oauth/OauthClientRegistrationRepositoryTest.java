package run.halo.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
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
}
