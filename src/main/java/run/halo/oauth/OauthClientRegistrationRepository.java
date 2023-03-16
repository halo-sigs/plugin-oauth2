package run.halo.oauth;

import static org.apache.commons.lang3.BooleanUtils.isTrue;
import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;

import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.AuthProvider;
import run.halo.app.extension.ConfigMap;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.extension.store.ExtensionStore;
import run.halo.app.infra.utils.JsonUtils;

/**
 * A reactive repository for OAuth 2.0 / OpenID Connect 1.0 ClientRegistration(s) that stores
 * {@link ClientRegistration}(s) in the {@link ExtensionStore}.
 *
 * @author guqing
 * @since 1.0.0
 */
@RequiredArgsConstructor
public class OauthClientRegistrationRepository implements ReactiveClientRegistrationRepository {
    static final String DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/code/{registrationId}";
    private final ReactiveExtensionClient client;

    @Override
    public Mono<ClientRegistration> findByRegistrationId(String registrationId) {
        return client.fetch(AuthProvider.class, registrationId)
            .filter(authProvider -> isTrue(authProvider.getSpec().getEnabled()))
            .switchIfEmpty(
                Mono.error(new ProviderNotFoundException(
                    "Unsupported OAuth2 provider: " + registrationId)))
            .flatMap(this::getClientRegistrationMono);
    }

    private Mono<ClientRegistration> getClientRegistrationMono(AuthProvider authProvider) {
        Assert.notNull(authProvider, "The authProvider must not be null");
        final AuthProvider.ConfigMapRef configMapKeyRef = authProvider.getSpec().getConfigMapRef();
        final String group = authProvider.getSpec().getSettingRef().getGroup();
        return client.fetch(ConfigMap.class, configMapKeyRef.getName())
            .map(ConfigMap::getData)
            .map(data -> {
                String value = data.get(group);
                if (StringUtils.isBlank(value)) {
                    return new ClientIdSecretPair("", "");
                }
                return JsonUtils.jsonToObject(value, ClientIdSecretPair.class);
            })
            .switchIfEmpty(
                Mono.error(new IllegalArgumentException(
                    "ConfigMap " + configMapKeyRef.getName() + " not found")
                )
            )
            .map(idSecretPair -> {
                if (StringUtils.isBlank(idSecretPair.clientId())) {
                    throw new IllegalArgumentException("clientId must not be blank");
                }
                if (StringUtils.isBlank(idSecretPair.clientSecret())) {
                    throw new IllegalArgumentException("clientSecret must not be blank");
                }
                return clientRegistrationBuilder(authProvider)
                    .clientId(idSecretPair.clientId())
                    .clientSecret(idSecretPair.clientSecret())
                    .build();
            });
    }

    record ClientIdSecretPair(String clientId, String clientSecret) {
        ClientIdSecretPair {
            if (StringUtils.isBlank(clientId)) {
                throw new IllegalArgumentException("clientId must not be blank");
            }
            if (StringUtils.isBlank(clientSecret)) {
                throw new IllegalArgumentException("clientSecret must not be blank");
            }
        }
    }

    ClientAuthenticationMethod toClientAuthenticationMethod(String method) {
        if (StringUtils.isBlank(method)) {
            return ClientAuthenticationMethod.NONE;
        }
        return new ClientAuthenticationMethod(method.toLowerCase());
    }

    AuthorizationGrantType toAuthorizationGrantType(String grantType) {
        if (StringUtils.isBlank(grantType)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        }
        return new AuthorizationGrantType(grantType.toLowerCase());
    }

    AuthenticationMethod toAuthenticationMethod(String method) {
        if (StringUtils.isBlank(method)) {
            return AuthenticationMethod.HEADER;
        }
        return new AuthenticationMethod(method.toLowerCase());
    }

    ClientRegistration.Builder clientRegistrationBuilder(AuthProvider authProvider) {
        AuthProvider.ClientRegistration registration =
            authProvider.getSpec().getClientRegistration();
        if (registration == null) {
            throw new IllegalArgumentException(
                "The clientRegistration in AuthProvider must not be null");
        }

        return ClientRegistration.withRegistrationId(authProvider.getMetadata().getName())
            .clientName(registration.getClientName())
            .clientAuthenticationMethod(
                toClientAuthenticationMethod(registration.getClientAuthenticationMethod())
            )
            .authorizationGrantType(
                toAuthorizationGrantType(registration.getAuthorizationGrantType())
            )
            .authorizationUri(registration.getAuthorizationUri())
            .issuerUri(registration.getIssuerUri())
            .jwkSetUri(registration.getJwkSetUri())
            .redirectUri(defaultIfNull(registration.getRedirectUri(), DEFAULT_REDIRECT_URL))
            .scope(registration.getScopes())
            .tokenUri(registration.getTokenUri())
            .userInfoAuthenticationMethod(
                toAuthenticationMethod(registration.getUserInfoAuthenticationMethod())
            )
            .userInfoUri(registration.getUserInfoUri())
            .providerConfigurationMetadata(
                defaultIfNull(registration.getConfigurationMetadata(), Map.of())
            )
            .userNameAttributeName(registration.getUserNameAttributeName());
    }
}
