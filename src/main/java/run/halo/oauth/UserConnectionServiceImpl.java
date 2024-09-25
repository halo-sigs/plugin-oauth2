package run.halo.oauth;

import static run.halo.app.extension.ExtensionUtil.defaultSort;
import static run.halo.app.extension.index.query.QueryFactory.and;
import static run.halo.app.extension.index.query.QueryFactory.equal;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.UserConnection;
import run.halo.app.extension.ListOptions;
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
    private final Oauth2LoginConfiguration oauth2LoginConfiguration;

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

    private Flux<UserConnection> listByRegistrationIdAndUsername(String registrationId, String username) {
        var listOptions = ListOptions.builder()
            .fieldQuery(and(
                equal("spec.registrationId", registrationId),
                equal("spec.username", username)
            ))
            .build();
        return client.listAll(UserConnection.class, listOptions, defaultSort());
    }

}
