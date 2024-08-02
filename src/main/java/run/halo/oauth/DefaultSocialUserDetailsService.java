package run.halo.oauth;

import java.util.Comparator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.UserConnection;
import run.halo.app.extension.ReactiveExtensionClient;

/**
 * Default social user details service.
 *
 * @author guqing
 * @since 1.0.0
 */
@Component
@RequiredArgsConstructor
public class DefaultSocialUserDetailsService implements SocialUserDetailsService {

    private final ReactiveExtensionClient client;
    private final ReactiveUserDetailsService userDetailsService;

    @Override
    public Mono<UserDetails> loadUserByUserId(String registrationId, String principalName)
        throws UsernameNotFoundException {
        return getUserConnectionByProviderUserId(registrationId, principalName)
            .flatMap(userConnection -> {
                String username = userConnection.getSpec().getUsername();
                return userDetailsService.findByUsername(username)
                    .switchIfEmpty(Mono.error(
                        new UsernameNotFoundException("User not found: " + username))
                    );
            });
    }

    Mono<UserConnection> getUserConnectionByProviderUserId(String registrationId,
        String providerUserId) {
        return client.list(UserConnection.class,
                connection -> connection.getSpec().getRegistrationId().equals(registrationId)
                    && connection.getSpec().getProviderUserId().equals(providerUserId),
                Comparator.comparing(item -> item.getMetadata()
                    .getCreationTimestamp())
            )
            .next()
            .switchIfEmpty(Mono.error(new UsernameNotFoundException(
                "The oauth2 account " + providerUserId
                    + " is not bound to a specified user.")));
    }
}
