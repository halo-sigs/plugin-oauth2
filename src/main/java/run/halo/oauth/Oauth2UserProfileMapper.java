package run.halo.oauth;

import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Mapping interface which can be implemented to map the user profile.
 *
 * @author guqing
 * @since 1.0.0
 */
public interface Oauth2UserProfileMapper {

    /**
     * Maps the user profile.
     *
     * @param oauth2User oauth2 user
     * @return oAuth2 user profile
     */
    Oauth2UserProfile mapProfile(OAuth2User oauth2User);

    /**
     * Whether the mapper supports the given registration id.
     *
     * @param registrationId registration id
     * @return true if the mapper supports the given registration id
     */
    boolean supports(String registrationId);
}
