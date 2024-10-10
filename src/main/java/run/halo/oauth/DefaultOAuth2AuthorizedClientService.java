package run.halo.oauth;

import java.util.Collections;
import java.util.Comparator;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;
import run.halo.app.extension.Metadata;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.security.authentication.oauth2.HaloOAuth2AuthenticationToken;

/**
 * Implementations of this interface are responsible for the management of Authorized Client(s),
 * which provide the purpose of associating an Access Token credential to a Client and Resource
 * Owner, who is the Principal that originally granted the authorization.
 *
 * @author guqing
 * @see ReactiveOAuth2AuthorizedClientService
 * @see JdbcOAuth2AuthorizedClientService
 * @see Oauth2LoginConfiguration
 * @since 1.0.0
 */
@RequiredArgsConstructor
public class DefaultOAuth2AuthorizedClientService implements ReactiveOAuth2AuthorizedClientService {

    private final ReactiveExtensionClient client;
    private final ReactiveClientRegistrationRepository clientRegistrationRepository;

    @Override
    @SuppressWarnings("unchecked")
    public <T extends OAuth2AuthorizedClient> Mono<T> loadAuthorizedClient(
        String clientRegistrationId, String principalName) {
        Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        return (Mono<T>) client.list(AuthorizedClient.class, authorizedClient ->
                    authorizedClient.getSpec().getRegistrationId().equals(clientRegistrationId)
                        && authorizedClient.getSpec().getPrincipalName().equals(principalName),
                Comparator.comparing(item -> item.getMetadata().getCreationTimestamp()))
            .next()
            .flatMap(authorizedClient -> this.clientRegistrationRepository.findByRegistrationId(
                    clientRegistrationId)
                .map(clientRegistration -> new OAuth2AuthorizedClient(clientRegistration,
                    principalName,
                    toAccessToken(authorizedClient),
                    toRefreshToken(authorizedClient))
                )
            );
    }

    @Override
    public Mono<Void> saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient,
        Authentication principal) {
        Assert.notNull(authorizedClient, "authorizedClient cannot be null");
        Assert.notNull(principal, "principal cannot be null");
        if (principal instanceof HaloOAuth2AuthenticationToken haloOAuthToken) {
            principal = haloOAuthToken.getOriginal();
        }
        String registrationId = authorizedClient.getClientRegistration().getRegistrationId();
        return client.fetch(AuthorizedClient.class,
                authorizedClientName(registrationId, principal.getName())
            )
            .flatMap(record -> {
                AuthorizedClient newRecord = toAuthorizedClient(authorizedClient);
                newRecord.getMetadata().setVersion(record.getMetadata().getVersion());
                return client.update(newRecord);
            })
            .switchIfEmpty(
                Mono.defer(() -> this.client.create(toAuthorizedClient(authorizedClient)))
            )
            .then();
    }

    @Override
    public Mono<Void> removeAuthorizedClient(String clientRegistrationId, String principalName) {
        Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        return client.fetch(AuthorizedClient.class, authorizedClientName(clientRegistrationId,
                principalName))
            .flatMap(client::delete)
            .then();
    }

    String authorizedClientName(String clientRegistrationId, String principalName) {
        return clientRegistrationId + "-" + principalName;
    }

    OAuth2AccessToken toAccessToken(AuthorizedClient authorizedClient) {
        OAuth2AccessToken.TokenType tokenType;
        if (OAuth2AccessToken.TokenType.BEARER.getValue()
            .equalsIgnoreCase(authorizedClient.getSpec().getAccessTokenType())) {
            tokenType = OAuth2AccessToken.TokenType.BEARER;
        } else {
            throw new IllegalArgumentException(
                "Invalid access token type: " + authorizedClient.getSpec().getAccessTokenType());
        }
        Set<String> scopes = Collections.emptySet();
        String accessTokenScopes = authorizedClient.getSpec().getAccessTokenScopes();
        if (accessTokenScopes != null) {
            scopes = StringUtils.commaDelimitedListToSet(accessTokenScopes);
        }
        return new OAuth2AccessToken(tokenType,
            authorizedClient.getSpec().getAccessTokenValue(),
            authorizedClient.getSpec().getAccessTokenIssuedAt(),
            authorizedClient.getSpec().getAccessTokenExpiresAt(),
            scopes);
    }

    OAuth2RefreshToken toRefreshToken(AuthorizedClient authorizedClient) {
        return new OAuth2RefreshToken(authorizedClient.getSpec().getRefreshTokenValue(),
            authorizedClient.getSpec().getRefreshTokenIssuedAt());
    }

    AuthorizedClient toAuthorizedClient(OAuth2AuthorizedClient param) {
        final String registrationId = param.getClientRegistration().getRegistrationId();
        AuthorizedClient authorizedClient = new AuthorizedClient();
        authorizedClient.setMetadata(new Metadata());
        authorizedClient.getMetadata()
            .setName(authorizedClientName(registrationId, param.getPrincipalName()));

        authorizedClient.setSpec(new AuthorizedClient.AuthorizedClientSpec());
        AuthorizedClient.AuthorizedClientSpec spec = authorizedClient.getSpec();

        spec.setPrincipalName(param.getPrincipalName());
        spec.setRegistrationId(registrationId);
        spec.setAccessTokenType(param.getAccessToken().getTokenType().getValue());
        spec.setAccessTokenValue(param.getAccessToken().getTokenValue());
        spec.setAccessTokenIssuedAt(param.getAccessToken().getIssuedAt());
        spec.setAccessTokenExpiresAt(param.getAccessToken().getExpiresAt());
        spec.setAccessTokenScopes(
            StringUtils.collectionToCommaDelimitedString(param.getAccessToken().getScopes()));

        if (param.getRefreshToken() != null) {
            spec.setRefreshTokenValue(param.getRefreshToken().getTokenValue());
            spec.setRefreshTokenIssuedAt(param.getRefreshToken().getIssuedAt());
        }
        return authorizedClient;
    }
}
