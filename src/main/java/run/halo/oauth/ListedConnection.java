package run.halo.oauth;

import lombok.Builder;
import lombok.Value;

/**
 * Connection information for listing.
 *
 * @author guqing
 * @since 1.0.0
 */
@Builder
@Value
public class ListedConnection {
    String registrationId;
    String username;
    String displayName;
    String profileUrl;
    String avatarUrl;
    SimpleAuthProvider provider;

    @Builder
    @Value
    public static class SimpleAuthProvider {
        String displayName;
        String logo;
        String website;
        String authenticationUrl;
        String helpPage;
    }
}
