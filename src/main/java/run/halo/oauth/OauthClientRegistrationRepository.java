package run.halo.oauth;

import static org.apache.commons.lang3.BooleanUtils.isTrue;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
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

    private final ReactiveExtensionClient client;

    @Override
    public Mono<ClientRegistration> findByRegistrationId(String registrationId) {
        CommonOAuth2Provider commonOauth2Provider = getCommonOauth2Provider(registrationId);

        return client.fetch(AuthProvider.class, registrationId)
            .filter(authProvider -> isTrue(authProvider.getSpec().getEnabled()))
            .switchIfEmpty(
                Mono.error(new ProviderNotFoundException(
                    "Unsupported OAuth2 provider: " + registrationId)))
            .flatMap(authProvider -> {
                AuthProvider.ConfigMapKeyRef configMapKeyRef =
                    authProvider.getSpec().getConfigMapKeyRef();
                return client.fetch(ConfigMap.class, configMapKeyRef.getName())
                    .map(ConfigMap::getData)
                    .map(data -> {
                        String value = data.get(configMapKeyRef.getKey());
                        return JsonUtils.jsonToObject(value, ClientIdSecretPair.class);
                    });
            })
            .map(idSecretPair -> commonOauth2Provider.getBuilder(registrationId)
                .clientId(idSecretPair.clientId())
                .clientSecret(idSecretPair.clientSecret())
                .build()
            );
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

    CommonOAuth2Provider getCommonOauth2Provider(String registrationId) {
        for (CommonOAuth2Provider provider : CommonOAuth2Provider.values()) {
            if (provider.name().equalsIgnoreCase(registrationId)) {
                return provider;
            }
        }
        throw new ProviderNotFoundException("Unsupported OAuth2 provider: " + registrationId);
    }
}
