package run.halo.oauth;

import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.AuthProvider;
import run.halo.app.extension.ConfigMap;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.infra.ExternalUrlSupplier;
import run.halo.app.infra.SystemSetting;
import run.halo.app.infra.utils.JsonUtils;

/**
 * A reactive repository for OAuth 2.0 / OpenID Connect 1.0 ClientRegistration(s) that stores
 * {@link ClientRegistration}(s) in the {@link ReactiveExtensionClient}.
 *
 * @author guqing
 * @since 1.0.0
 */
@RequiredArgsConstructor
public class OauthClientRegistrationRepository implements ReactiveClientRegistrationRepository {
    static final String DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/code/{registrationId}";
    static final String ADVANCED_OIDC_SETTING_GROUP = "ssoOauth";
    static final String LOGTO_SETTING_GROUP = "logtoOauth";
    static final String JWS_ALGORITHM_METADATA_KEY = "jwsAlgorithm";
    private final ReactiveExtensionClient client;
    private final ExternalUrlSupplier externalUrlSupplier;

    @Override
    public Mono<ClientRegistration> findByRegistrationId(String registrationId) {
        return client.fetch(AuthProvider.class, registrationId)
            .switchIfEmpty(
                Mono.error(new ProviderNotFoundException(
                    "Unsupported OAuth2 provider: " + registrationId)))
            .flatMap(provider -> fetchEnabledProviders()
                .doOnNext(enabledNames -> {
                    if (!enabledNames.contains(registrationId)) {
                        throw new OAuth2AuthenticationException(
                            "Authentication provider is not enabled: " + registrationId);
                    }
                })
                .thenReturn(provider)
            )
            .flatMap(this::getClientRegistrationMono);
    }

    private Mono<ClientRegistration> getClientRegistrationMono(AuthProvider authProvider) {
        Assert.notNull(authProvider, "The authProvider must not be null");
        final AuthProvider.ConfigMapRef configMapKeyRef = authProvider.getSpec().getConfigMapRef();
        final String group = authProvider.getSpec().getSettingRef().getGroup();
        final String name = authProvider.getMetadata().getName();
        return client.fetch(ConfigMap.class, configMapKeyRef.getName())
            .map(ConfigMap::getData)
            .switchIfEmpty(
                Mono.error(new IllegalArgumentException(
                    "ConfigMap " + configMapKeyRef.getName() + " not found")
                )
            )
            .flatMap(data -> {
                String value = data.getOrDefault(group, "{}");
                if (LOGTO_SETTING_GROUP.equals(group)) {
                    if (StringUtils.isBlank(value) || "{}".equals(value.trim())) {
                        String legacyValue = data.getOrDefault(ADVANCED_OIDC_SETTING_GROUP, "{}");
                        if (!"{}".equals(legacyValue.trim())) {
                            SsoClientConf ssoClientConf =
                                JsonUtils.jsonToObject(legacyValue, SsoClientConf.class);
                            return SsoClientRegistration(ssoClientConf, authProvider);
                        }
                    }
                    LogtoClientConf logtoClientConf =
                        JsonUtils.jsonToObject(value, LogtoClientConf.class);
                    return LogtoClientRegistration(logtoClientConf, authProvider);
                }
                if (ADVANCED_OIDC_SETTING_GROUP.equals(group)) {
                    SsoClientConf ssoClientConf =
                        JsonUtils.jsonToObject(value, SsoClientConf.class);
                    return SsoClientRegistration(ssoClientConf, authProvider);
                }

                GenericClientConf genericClientConf =
                    JsonUtils.jsonToObject(value, GenericClientConf.class);
                return GenericClientRegistration(genericClientConf, authProvider);
            });
    }

    private Mono<ClientRegistration> GenericClientRegistration(GenericClientConf genericClientConf,
        AuthProvider authProvider) {
        if (StringUtils.isBlank(genericClientConf.clientId())) {
            return Mono.error(new IllegalArgumentException("clientId must not be blank"));
        }
        if (StringUtils.isBlank(genericClientConf.clientSecret())) {
            return Mono.error(
                new IllegalArgumentException("clientSecret must not be blank"));
        }
        String registrationId = authProvider.getMetadata().getName();
        return client.fetch(Oauth2ClientRegistration.class, registrationId)
            .switchIfEmpty(Mono.error(new NotFoundException(
                "Oauth2 client registration " + registrationId + " not found")
            ))
            .map(oauth2ClientRegistration -> clientRegistrationBuilder(
                oauth2ClientRegistration)
                .clientId(genericClientConf.clientId())
                .clientSecret(genericClientConf.clientSecret())
                .build()
            );
    }

    private Mono<ClientRegistration> LogtoClientRegistration(LogtoClientConf logtoClientConf,
        AuthProvider authProvider) {
        String registrationId = authProvider.getMetadata().getName();
        var issuerUri = normalizeLogtoIssuerUri(logtoClientConf.endpoint());
        return client.fetch(Oauth2ClientRegistration.class, registrationId)
            .switchIfEmpty(Mono.error(new NotFoundException(
                "Oauth2 client registration " + registrationId + " not found")
            ))
            .map(oauth2ClientRegistration -> clientRegistrationBuilder(oauth2ClientRegistration)
                .clientId(logtoClientConf.clientId())
                .clientSecret(logtoClientConf.clientSecret())
                .authorizationUri(issuerUri + "/auth")
                .tokenUri(issuerUri + "/token")
                .userInfoUri(issuerUri + "/me")
                .jwkSetUri(issuerUri + "/jwks")
                .issuerUri(issuerUri)
                .userNameAttributeName("sub")
                .build()
            );
    }

    private Mono<ClientRegistration> SsoClientRegistration(SsoClientConf ssoClientConf,
        AuthProvider authProvider) {
        String registrationId = authProvider.getMetadata().getName();
        return client.fetch(Oauth2ClientRegistration.class, registrationId)
            .switchIfEmpty(Mono.error(new NotFoundException(
                "Oauth2 client registration " + registrationId + " not found")
            ))
            .map(oauth2ClientRegistration -> {
                ClientRegistration.Builder builder =
                    clientRegistrationBuilder(oauth2ClientRegistration)
                        .clientId(ssoClientConf.clientId())
                        .clientSecret(ssoClientConf.clientSecret())
                        .authorizationUri(ssoClientConf.authorizationUrl())
                        .tokenUri(ssoClientConf.tokenUrl())
                        .userInfoUri(ssoClientConf.userInfoUrl())
                        .userNameAttributeName(ssoClientConf.userNameAttribute());

                if (StringUtils.isNotBlank(ssoClientConf.issuerUri())) {
                    builder.issuerUri(ssoClientConf.issuerUri());
                }
                if (StringUtils.isNotBlank(ssoClientConf.jwkSetUri())) {
                    builder.jwkSetUri(ssoClientConf.jwkSetUri());
                }

                // e.g. "openid profile", "openid,profile" or "openid, profile"
                String scopesStr = ssoClientConf.scopes();
                if (!StringUtils.isBlank(scopesStr)) {
                    Set<String> scopes = Arrays.stream(scopesStr.split("\\s+|,\\s*"))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet());
                    builder.scope(scopes);
                }

                return builder.build();
            });
    }

    record GenericClientConf(String clientId, String clientSecret) {
        GenericClientConf {
            if (StringUtils.isBlank(clientId)) {
                throw new IllegalArgumentException("clientId must not be blank");
            }
            if (StringUtils.isBlank(clientSecret)) {
                throw new IllegalArgumentException("clientSecret must not be blank");
            }
        }
    }

    record LogtoClientConf(String clientId, String clientSecret, String endpoint) {
        LogtoClientConf {
            if (StringUtils.isBlank(clientId)) {
                throw new IllegalArgumentException("clientId must not be blank");
            }
            if (StringUtils.isBlank(clientSecret)) {
                throw new IllegalArgumentException("clientSecret must not be blank");
            }
            if (StringUtils.isBlank(endpoint)) {
                throw new IllegalArgumentException("endpoint must not be blank");
            }
        }
    }

    record SsoClientConf(String clientId, String clientSecret, String authorizationUrl,
                         String tokenUrl, String userInfoUrl, String scopes,
                         String userNameAttribute, String issuerUri, String jwkSetUri) {
        SsoClientConf {
            if (StringUtils.isBlank(clientId)) {
                throw new IllegalArgumentException("clientId must not be blank");
            }
            if (StringUtils.isBlank(clientSecret)) {
                throw new IllegalArgumentException("clientSecret must not be blank");
            }
            if (StringUtils.isBlank(authorizationUrl)) {
                throw new IllegalArgumentException("authorizationUrl must not be blank");
            }
            if (StringUtils.isBlank(tokenUrl)) {
                throw new IllegalArgumentException("tokenUrl must not be blank");
            }
            if (StringUtils.isBlank(userInfoUrl)) {
                throw new IllegalArgumentException("userInfoUrl must not be blank");
            }
            if (StringUtils.isBlank(scopes)) {
                throw new IllegalArgumentException("scopes must not be blank");
            }
            if (StringUtils.isBlank(userNameAttribute)) {
                throw new IllegalArgumentException("userNameAttribute must not be blank");
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

    ClientRegistration.Builder clientRegistrationBuilder(Oauth2ClientRegistration registration) {
        if (registration == null) {
            throw new IllegalArgumentException(
                "The clientRegistration in AuthProvider must not be null");
        }
        Oauth2ClientRegistration.Oauth2ClientRegistrationSpec spec = registration.getSpec();
        var redirectUri = defaultIfNull(spec.getRedirectUri(), DEFAULT_REDIRECT_URL);
        var externalUrl = externalUrlSupplier.getRaw();
        if (externalUrl != null) {
            // rewrite redirect URI if external Url is configured.
            redirectUri = UriComponentsBuilder.fromUriString(redirectUri)
                .uriVariables(Map.of("baseUrl", StringUtils.removeEnd(externalUrl.toString(), "/")))
                .build()
                .toString();
        }
        return ClientRegistration.withRegistrationId(registration.getMetadata().getName())
            .clientName(spec.getClientName())
            .clientAuthenticationMethod(
                toClientAuthenticationMethod(spec.getClientAuthenticationMethod())
            )
            .authorizationGrantType(
                toAuthorizationGrantType(spec.getAuthorizationGrantType())
            )
            .authorizationUri(spec.getAuthorizationUri())
            .issuerUri(spec.getIssuerUri())
            .jwkSetUri(spec.getJwkSetUri())
            .redirectUri(redirectUri)
            .scope(spec.getScopes())
            .tokenUri(spec.getTokenUri())
            .userInfoAuthenticationMethod(
                toAuthenticationMethod(spec.getUserInfoAuthenticationMethod())
            )
            .userInfoUri(spec.getUserInfoUri())
            .providerConfigurationMetadata(buildProviderConfigurationMetadata(spec))
            .userNameAttributeName(spec.getUserNameAttributeName());
    }

    private Map<String, Object> buildProviderConfigurationMetadata(
        Oauth2ClientRegistration.Oauth2ClientRegistrationSpec spec) {
        if (StringUtils.isBlank(spec.getJwsAlgorithm())) {
            return Map.of();
        }
        return Map.of(JWS_ALGORITHM_METADATA_KEY, spec.getJwsAlgorithm());
    }

    private String normalizeLogtoIssuerUri(String endpoint) {
        String normalized = StringUtils.removeEnd(endpoint.trim(), "/");
        for (String suffix : List.of("/auth", "/token", "/me", "/jwks")) {
            normalized = StringUtils.removeEnd(normalized, suffix);
        }
        if (!normalized.endsWith("/oidc")) {
            normalized = normalized + "/oidc";
        }
        return normalized;
    }

    Mono<Set<String>> fetchEnabledProviders() {
        return client.fetch(ConfigMap.class, SystemSetting.SYSTEM_CONFIG)
            .map(configMap -> {
                var authProvider = getAuthProvider(configMap);
                return authProvider.getStates().stream()
                    .filter(SystemSetting.AuthProviderState::isEnabled)
                    .map(SystemSetting.AuthProviderState::getName)
                    .collect(Collectors.toSet());
            })
            .defaultIfEmpty(Set.of());
    }

    @NonNull
    private static SystemSetting.AuthProvider getAuthProvider(ConfigMap configMap) {
        if (configMap.getData() == null) {
            configMap.setData(new HashMap<>());
        }

        Map<String, String> data = configMap.getData();
        String providerGroup = data.get(SystemSetting.AuthProvider.GROUP);
        SystemSetting.AuthProvider authProvider;
        if (StringUtils.isBlank(providerGroup)) {
            authProvider = new SystemSetting.AuthProvider();
        } else {
            authProvider = JsonUtils.jsonToObject(providerGroup, SystemSetting.AuthProvider.class);
        }

        if (authProvider.getStates() == null) {
            authProvider.setStates(List.of());
        }
        return authProvider;
    }
}
