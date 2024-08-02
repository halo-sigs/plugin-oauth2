package run.halo.oauth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.UserConnection;

/**
 * Similar to {@link UserDetailsService} but loads details by user's identity at the provider,
 * not username.
 *
 * @author guqing
 * @since 1.0.0
 */
public interface SocialUserDetailsService {

    /**
     * Loads the user details by the user's identity at the provider.
     *
     * @param registrationId the {@link UserConnection.UserConnectionSpec#getRegistrationId()}
     * @param principalName the {@link UserConnection.UserConnectionSpec#getProviderUserId()} used
     * to look up the user details
     * @return the user details
     * @throws UsernameNotFoundException if the user details cannot be found
     */
    Mono<UserDetails> loadUserByUserId(String registrationId, String principalName)
        throws UsernameNotFoundException;
}
