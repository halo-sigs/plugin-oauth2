package run.halo.oauth;

import static io.swagger.v3.oas.annotations.media.Schema.RequiredMode.REQUIRED;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import run.halo.app.extension.AbstractExtension;
import run.halo.app.extension.GVK;

/**
 * Oauth2 authorized client.
 *
 * @author guqing
 * @see InMemoryReactiveOAuth2AuthorizedClientService
 * @see OAuth2AuthorizedClient
 * @see
 * <a href="https://github.com/spring-projects/spring-security/blob/8c17b978c881fb0df3961cbc7f4a01c6f97deede/oauth2/oauth2-client/src/main/resources/org/springframework/security/oauth2/client/oauth2-client-schema.sql#L1-L13>oauth2-client-schema.sql</a>
 * @since 1.0.0
 */
@Data
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
@GVK(group = "oauth.halo.run", version = "v1alpha1", kind = "AuthorizedClient",
    plural = "authorizedclients", singular = "authorizedclient")
public class AuthorizedClient extends AbstractExtension {

    @Schema(requiredMode = REQUIRED)
    private AuthorizedClientSpec spec;

    @Data
    @ToString
    public static class AuthorizedClientSpec {

        @Schema(requiredMode = REQUIRED)
        private String registrationId;

        @Schema(requiredMode = REQUIRED)
        private String principalName;

        @Schema(requiredMode = REQUIRED)
        private String accessTokenType;

        @Schema(requiredMode = REQUIRED)
        private String accessTokenValue;

        @Schema(requiredMode = REQUIRED)
        private Instant accessTokenIssuedAt;

        @Schema(requiredMode = REQUIRED)
        private Instant accessTokenExpiresAt;

        private String accessTokenScopes;

        private String refreshTokenValue;

        private Instant refreshTokenIssuedAt;
    }
}
