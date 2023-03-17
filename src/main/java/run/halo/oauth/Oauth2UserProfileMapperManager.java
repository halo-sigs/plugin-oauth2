package run.halo.oauth;

import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.NonNull;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

/**
 * Oauth2 user profile mapper manager.
 *
 * @author guqing
 * @since 1.0.0
 */
@Component
@RequiredArgsConstructor
public class Oauth2UserProfileMapperManager {
    private final ApplicationContext applicationContext;

    /**
     * Maps the user profile.
     *
     * @param registrationId registration id
     * @param oauth2User oauth2 user
     * @return oAuth2 user profile
     */
    @NonNull
    public Oauth2UserProfile mapProfile(String registrationId, OAuth2User oauth2User) {
        return applicationContext.getBeanProvider(Oauth2UserProfileMapper.class)
            .orderedStream()
            .filter(mapper -> mapper.supports(registrationId))
            .findFirst()
            .map(mapper -> mapper.mapProfile(oauth2User))
            .orElseThrow(() -> new IllegalArgumentException(
                "No Oauth2UserProfileMapper found for registration id: " + registrationId));
    }
}
