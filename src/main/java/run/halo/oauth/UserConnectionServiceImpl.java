package run.halo.oauth;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.AuthProvider;
import run.halo.app.core.extension.UserConnection;
import run.halo.app.extension.Metadata;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.infra.exception.AccessDeniedException;

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
        if (StringUtils.isBlank(username)) {
            throw new AccessDeniedException(
                "Binding cannot be completed without user authentication");
        }

        UserConnection connection = convert(username, authentication);
        return fetchUserConnection(username, connection.getSpec().getRegistrationId())
            .flatMap(persisted -> {
                connection.getMetadata().setName(persisted.getMetadata().getName());
                connection.getMetadata()
                    .setVersion(persisted.getMetadata().getVersion());
                return client.update(connection);
            })
            .switchIfEmpty(Mono.defer(() -> client.create(connection)));
    }

    @Override
    public Mono<UserConnection> removeConnection(String registrationId) {
        return ReactiveSecurityContextHolder.getContext()
            .map(securityContext -> securityContext.getAuthentication().getName())
            .switchIfEmpty(Mono.error(
                new AccessDeniedException("Cannot disconnect without user authentication"))
            )
            .flatMap(username -> fetchUserConnection(registrationId, username)
                .flatMap(userConnection -> {
                    String providerUserId = userConnection.getSpec().getProviderUserId();
                    return oauth2LoginConfiguration.getAuthorizedClientService()
                        .removeAuthorizedClient(registrationId, providerUserId)
                        .then(client.delete(userConnection));
                })
            );
    }

    private Mono<ListedConnection> convertTo(UserConnection userConnection) {
        String registrationId = userConnection.getSpec().getRegistrationId();
        var builder = ListedConnection.builder()
            .displayName(userConnection.getSpec().getDisplayName())
            .avatarUrl(userConnection.getSpec().getAvatarUrl())
            .username(userConnection.getSpec().getProviderUserId())
            .profileUrl(userConnection.getSpec().getProfileUrl())
            .registrationId(userConnection.getSpec().getRegistrationId());
        return client.fetch(AuthProvider.class, registrationId)
            .map(authProvider -> ListedConnection.SimpleAuthProvider.builder()
                .displayName(authProvider.getSpec().getDisplayName())
                .logo(authProvider.getSpec().getLogo())
                .website(authProvider.getSpec().getWebsite())
                .helpPage(authProvider.getSpec().getHelpPage())
                .authenticationUrl(authProvider.getSpec().getAuthenticationUrl())
                .build()
            )
            .map(provider -> {
                builder.provider(provider);
                return builder.build();
            });
    }

    private Mono<UserConnection> fetchUserConnection(String registrationId, String username) {
        return client.list(UserConnection.class, persisted -> persisted.getSpec()
                .getUsername().equals(username)
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
