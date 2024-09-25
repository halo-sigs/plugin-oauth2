package run.halo.oauth;

import reactor.core.publisher.Flux;
import run.halo.app.core.extension.UserConnection;

/**
 * User connection service.
 *
 * @author guqing
 * @since 1.0.0
 */
@Deprecated(forRemoval = true)
public interface UserConnectionService {

    Flux<UserConnection> removeConnection(String registrationId);

}
