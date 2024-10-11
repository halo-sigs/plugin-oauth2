package run.halo.oauth;

import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.stereotype.Component;
import run.halo.app.event.user.UserConnectionDisconnectedEvent;

/**
 * An event listener that will remove the authorized client after a user connection is disconnected.
 *
 * @author johnniang
 * @since 2.20.0
 */
@Slf4j
@Component
public class UserConnectionDisconnectedListener
    implements ApplicationListener<UserConnectionDisconnectedEvent> {

    private final ReactiveOAuth2AuthorizedClientService authorizedClientService;

    public UserConnectionDisconnectedListener(Oauth2LoginConfiguration configuration) {
        authorizedClientService = configuration.getAuthorizedClientService();
    }

    @Override
    @Async
    public void onApplicationEvent(UserConnectionDisconnectedEvent event) {
        var connection = event.getUserConnection();
        var registrationId = connection.getSpec().getRegistrationId();
        var providerUserId = connection.getSpec().getProviderUserId();
        authorizedClientService.removeAuthorizedClient(registrationId, providerUserId)
            .blockOptional(Duration.ofMinutes(1));
        if (log.isDebugEnabled()) {
            log.debug("Cleanup authorized client for user connection [{}].", connection);
        }
    }

}
