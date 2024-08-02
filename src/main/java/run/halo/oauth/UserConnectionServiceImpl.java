package run.halo.oauth;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebInputException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.UserConnection;
import run.halo.app.extension.Metadata;
import run.halo.app.extension.ReactiveExtensionClient;

/**
 * User connection service implementation.
 *
 * @author guqing
 * @since 1.0.0
 */
@Component
@RequiredArgsConstructor
public class UserConnectionServiceImpl implements UserConnectionService {

    private final ReactiveExtensionClient client;
    private final Oauth2UserProfileMapperManager oauth2UserProfileMapperManager;
    private final Oauth2LoginConfiguration oauth2LoginConfiguration;

    @Override
    public Mono<UserConnection> createConnection(String username,
                                                 OAuth2LoginAuthenticationToken authentication) {
        Assert.notNull(authentication, "OAuth2LoginAuthenticationToken must not be null");
        if (StringUtils.isBlank(username)) {
            throw new AccessDeniedException(
                "Binding cannot be completed without user authentication");
        }

        UserConnection connection = convert(username, authentication);
        String providerUserId = authentication.getPrincipal().getName();
        return findByRegistrationId(connection.getSpec().getRegistrationId())
            .hasElement()
            .flatMap(exists -> {
                if (exists) {
                    return Mono.error(new ServerWebInputException(
                        "已经绑定过 " + connection.getSpec().getRegistrationId() + " 账号，请先解绑"));
                }
                return fetchUserConnection(connection.getSpec().getRegistrationId(), providerUserId)
                    .flatMap(persisted -> {
                        connection.getMetadata().setName(persisted.getMetadata().getName());
                        connection.getMetadata()
                            .setVersion(persisted.getMetadata().getVersion());
                        return client.update(connection);
                    })
                    .switchIfEmpty(Mono.defer(() -> client.create(connection)));
            });
    }

    @Override
    public Flux<UserConnection> removeConnection(String registrationId) {
        return ReactiveSecurityContextHolder.getContext()
            .map(securityContext -> securityContext.getAuthentication().getName())
            .switchIfEmpty(Mono.error(
                new AccessDeniedException("Cannot disconnect without user authentication"))
            )
            .flatMapMany(username -> listByRegistrationIdAndUsername(registrationId, username)
                .flatMap(userConnection -> {
                    String providerUserId = userConnection.getSpec().getProviderUserId();
                    return oauth2LoginConfiguration.getAuthorizedClientService()
                        .removeAuthorizedClient(registrationId, providerUserId)
                        .then(Mono.defer(() -> client.delete(userConnection)));
                })
            );
    }

    @Override
    public Mono<Boolean> isConnected(String registrationId, String providerUserId) {
        return client.list(UserConnection.class, persisted -> persisted.getSpec()
                .getProviderUserId().equals(providerUserId)
                && persisted.getSpec().getRegistrationId().equals(registrationId), null)
            .next()
            .hasElement();
    }

    Flux<UserConnection> listByRegistrationIdAndUsername(String registrationId, String username) {
        return client.list(UserConnection.class, persisted -> persisted.getSpec()
            .getRegistrationId().equals(registrationId)
            && persisted.getSpec().getUsername().equals(username), null);
    }

    private Mono<UserConnection> findByRegistrationId(String registrationId) {
        return client.list(UserConnection.class,
                persisted -> persisted.getSpec().getRegistrationId().equals(registrationId), null)
            .next();
    }

    private Mono<UserConnection> fetchUserConnection(String registrationId, String providerUserId) {
        return client.list(UserConnection.class, persisted -> persisted.getSpec()
                .getProviderUserId().equals(providerUserId)
                && persisted.getSpec().getRegistrationId().equals(registrationId), null)
            .next();
    }

    UserConnection convert(String username, OAuth2LoginAuthenticationToken authentication) {
        UserConnection userConnection = new UserConnection();
        userConnection.setMetadata(new Metadata());
        userConnection.getMetadata().setGenerateName("connection-");
        userConnection.getMetadata().setName("");

        OAuth2User oauth2User = authentication.getPrincipal();
        final String registrationId = authentication.getClientRegistration().getRegistrationId();

        UserConnection.UserConnectionSpec spec =
            new UserConnection.UserConnectionSpec();
        userConnection.setSpec(spec);
        spec.setUsername(username);
        spec.setProviderUserId(oauth2User.getName());
        spec.setRegistrationId(registrationId);
        spec.setAccessToken(authentication.getAccessToken().getTokenValue());
        spec.setExpiresAt(authentication.getAccessToken().getExpiresAt());
        if (authentication.getRefreshToken() != null) {
            spec.setRefreshToken(authentication.getRefreshToken().getTokenValue());
        }

        Oauth2UserProfile oauth2UserProfile =
            oauth2UserProfileMapperManager.mapProfile(registrationId, oauth2User);
        spec.setDisplayName(oauth2UserProfile.getDisplayName());
        spec.setAvatarUrl(oauth2UserProfile.getAvatarUrl());
        spec.setProfileUrl(oauth2UserProfile.getProfileUrl());
        return userConnection;
    }
}
