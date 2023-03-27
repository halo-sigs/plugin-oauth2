package run.halo.oauth;

import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

/**
 * A generic oauth2 user profile mapper.
 *
 * @author guqing
 * @since 1.0.0
 */
@Component
public class GenericUserProfileMapper implements Oauth2UserProfileMapper {

    @Override
    public Oauth2UserProfile mapProfile(OAuth2User oauth2User) {
        return Oauth2UserProfile.builder()
            .displayName(oauth2User.getAttribute("name"))
            .username(oauth2User.getAttribute("login"))
            .avatarUrl(oauth2User.getAttribute("avatar_url"))
            .profileUrl(oauth2User.getAttribute("html_url"))
            .build();
    }

    @Override
    public boolean supports(String registrationId) {
        Assert.hasText(registrationId, "Registration id must not be blank");
        return true;
    }
}
