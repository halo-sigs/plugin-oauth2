package run.halo.oauth;

import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.UserConnection;

/**
 * User connection service.
 *
 * @author guqing
 * @since 1.0.0
 */
public interface UserConnectionService {

    /**
     * Creates a new user connection by the given authentication.
     * If the user connection already exists, will update it and return,
     * otherwise will create a new user connection and return.
     *
     * @param authentication oauth2 login authentication token
     * @return user connection
     */
    Mono<UserConnection> createConnection(String username,
        OAuth2LoginAuthenticationToken authentication);


    Mono<UserConnection> removeConnection(String registrationId);
}
