package run.halo.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

class HaloOAuth2AuthenticationWebFilterTest {

    @Test
    void explicitJwsAlgorithmShouldTakePrecedence() {
        var registration = registrationBuilder()
            .providerConfigurationMetadata(
                Map.of(
                    "jwsAlgorithm", "ES384",
                    "id_token_signing_alg_values_supported", List.of("RS256")
                )
            )
            .build();

        assertThat(resolveJwsAlgorithm(registration)).isEqualTo(SignatureAlgorithm.ES384);
    }

    @Test
    void metadataSupportedAlgorithmsShouldFallbackToFirstValue() {
        var registration = registrationBuilder()
            .providerConfigurationMetadata(
                Map.of("id_token_signing_alg_values_supported", List.of("ES384", "RS256"))
            )
            .build();

        assertThat(resolveJwsAlgorithm(registration)).isEqualTo(SignatureAlgorithm.ES384);
    }

    @Test
    void shouldFallbackToDefaultRs256WhenMetadataIsMissing() {
        var registration = registrationBuilder().build();

        assertThat(resolveJwsAlgorithm(registration)).isEqualTo(SignatureAlgorithm.RS256);
    }

    private static ClientRegistration.Builder registrationBuilder() {
        return ClientRegistration.withRegistrationId("logto")
            .clientId("client-id")
            .clientSecret("client-secret")
            .clientName("Logto")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .redirectUri("{baseUrl}/login/oauth2/code/logto")
            .authorizationUri("https://logto.example.com/oidc/auth")
            .tokenUri("https://logto.example.com/oidc/token")
            .userInfoUri("https://logto.example.com/oidc/me")
            .jwkSetUri("https://logto.example.com/oidc/jwks")
            .userNameAttributeName("sub");
    }

    private static SignatureAlgorithm resolveJwsAlgorithm(ClientRegistration registration) {
        try {
            Method method = HaloOAuth2AuthenticationWebFilter.class.getDeclaredMethod(
                "resolveJwsAlgorithm", ClientRegistration.class
            );
            method.setAccessible(true);
            return (SignatureAlgorithm) method.invoke(null, registration);
        } catch (NoSuchMethodException e) {
            fail("Expected resolveJwsAlgorithm(ClientRegistration) helper to exist", e);
        } catch (IllegalAccessException | InvocationTargetException e) {
            fail("Failed to invoke resolveJwsAlgorithm(ClientRegistration)", e);
        }
        throw new IllegalStateException("Unreachable");
    }
}
