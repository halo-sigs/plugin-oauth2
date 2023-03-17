package run.halo.oauth;

import static io.swagger.v3.oas.annotations.media.Schema.RequiredMode.REQUIRED;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Value;

/**
 * Oauth2 user profile.
 *
 * @author guqing
 * @since 1.0.0
 */
@Builder
@Value
public class Oauth2UserProfile {

    /**
     * The unique identifier for the user's connection to the OAuth provider.
     * for example, the user's GitHub id.
     */
    @Schema(requiredMode = REQUIRED)
    String username;

    /**
     * The display name for the user's connection to the OAuth provider.
     */
    @Schema(requiredMode = REQUIRED)
    String displayName;

    /**
     * The URL to the user's profile page on the OAuth provider.
     * For example, the user's GitHub profile URL.
     */
    String profileUrl;

    /**
     * The URL to the user's avatar image on the OAuth provider.
     * For example, the user's GitHub avatar URL.
     */
    String avatarUrl;
}
