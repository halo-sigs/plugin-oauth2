package run.halo.oauth;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * <p>A subclass of {@link DefaultServerOAuth2AuthorizationRequestResolver} that supports social
 * connection request resolver.
 * If the {@link ServerWebExchange#getRequest()} contains a {@link #SOCIAL_CONNECTION} parameter,
 * the {@link OAuth2AuthorizationRequest} will be added a {@link #SOCIAL_CONNECTION} attribute to
 * the additionalParameters.
 * </p>
 * The {@link ClientRegistration#getRegistrationId()} is extracted from the request using
 * the {@link #DEFAULT_AUTHORIZATION_REQUEST_PATTERN}. The injected
 * {@link ReactiveClientRegistrationRepository} is then used to resolve the
 * {@link ClientRegistration} and create the {@link OAuth2AuthorizationRequest}.
 *
 * @author guqing
 * @see
 * <a href="https://docs.spring.io/spring-security/reference/reactive/oauth2/client/authorization-grants.html">Spring security authorization-grants</a>
 * @since 1.0.0
 */
public class SocialServerOauth2AuthorizationRequestResolver extends
    DefaultServerOAuth2AuthorizationRequestResolver {

    public static final String SOCIAL_CONNECTION = "social_connection";

    public SocialServerOauth2AuthorizationRequestResolver(
        ReactiveClientRegistrationRepository clientRegistrationRepository) {
        super(clientRegistrationRepository);
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange,
        String clientRegistrationId) {
        return super.resolve(exchange, clientRegistrationId)
            .map(authorizationRequest -> {
                OAuth2AuthorizationRequest.Builder builder =
                    OAuth2AuthorizationRequest.from(authorizationRequest);
                var queryParams = exchange.getRequest()
                    .getQueryParams().toSingleValueMap();
                builder.additionalParameters(
                    params -> queryParams.forEach(params::putIfAbsent));
                return builder.build();
            });
    }
}
