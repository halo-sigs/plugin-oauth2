package run.halo.oauth;

import static org.springdoc.core.fn.builders.apiresponse.Builder.responseBuilder;
import static org.springdoc.core.fn.builders.parameter.Builder.parameterBuilder;

import io.swagger.v3.oas.annotations.enums.ParameterIn;
import java.net.URI;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.BooleanUtils;
import org.springdoc.webflux.core.fn.SpringdocRouteBuilder;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.endpoint.CustomEndpoint;

/**
 * User connection endpoint.
 *
 * @author guqing
 * @since 1.0.0
 */
@Component
@RequiredArgsConstructor
public class UserConnectionEndpoint implements CustomEndpoint {

    private final UserConnectionService userConnectionService;

    @Override
    public RouterFunction<ServerResponse> endpoint() {
        final var tag = "api.console.halo.run/v1alpha1/Connection";
        return SpringdocRouteBuilder.route()
            .GET("/connect/{registrationId}", this::connect,
                builder -> builder.operationId("Connect")
                    .description("Connect to the third-party platform.")
                    .tag(tag)
                    .parameter(parameterBuilder().name("registrationId")
                        .in(ParameterIn.PATH)
                        .required(true)
                        .implementation(String.class))
            )
            .GET("connections/-", this::myConnections,
                builder -> builder.operationId("myConnections")
                    .description("Lists the third-party accounts information bound by myself.")
                    .tag(tag)
                    .response(responseBuilder()
                        .implementation(ListedConnection.class)
                    )
            )
            .build();
    }

    Mono<ServerResponse> connect(ServerRequest request) {
        String registrationId = request.pathVariable("registrationId");
        return ServerResponse.temporaryRedirect(buildOauthRedirectUri(registrationId))
            .build();
    }

    Mono<ServerResponse> myConnections(ServerRequest request) {
        return userConnectionService.listMyConnections()
            .collectList()
            .flatMap(result -> ServerResponse.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(result)
            );
    }

    URI buildOauthRedirectUri(String registrationId) {
        return UriComponentsBuilder.fromPath("/oauth2/authorization/{registrationId}")
            .uriVariables(Map.of("registrationId", registrationId))
            .queryParam(SocialServerOauth2AuthorizationRequestResolver.SOCIAL_CONNECTION,
                BooleanUtils.TRUE)
            .build()
            .toUri();
    }
}
