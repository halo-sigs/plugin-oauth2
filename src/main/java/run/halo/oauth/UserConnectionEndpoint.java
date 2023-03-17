package run.halo.oauth;

import static org.springdoc.core.fn.builders.apiresponse.Builder.responseBuilder;
import static org.springdoc.core.fn.builders.parameter.Builder.parameterBuilder;

import io.swagger.v3.oas.annotations.enums.ParameterIn;
import java.net.URI;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.BooleanUtils;
import org.springdoc.webflux.core.fn.SpringdocRouteBuilder;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.endpoint.CustomEndpoint;
import run.halo.app.extension.GroupVersion;

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
    private final String tag = "api.plugin.halo.run/v1alpha1/Connection";

    @Override
    public RouterFunction<ServerResponse> endpoint() {
        return SpringdocRouteBuilder.route()
            .nest(RequestPredicates.path("/plugins/plugin-oauth-github"), this::nested,
                builder -> builder.operationId("PluginOauthGithubEndpoints")
                    .description("Plugin OAuth GitHub Endpoints").tag(tag)
            )
            .build();
    }

    RouterFunction<ServerResponse> nested() {
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
            .POST("/disconnect/{registrationId}", this::disconnect,
                builder -> builder.operationId("Disconnect")
                    .description("Disconnect a third-party platform.")
                    .tag(tag)
                    .parameter(parameterBuilder().name("registrationId")
                        .in(ParameterIn.PATH)
                        .required(true)
                        .implementation(String.class))
            )
            .build();
    }

    @Override
    public GroupVersion groupVersion() {
        return GroupVersion.parseAPIVersion("api.plugin.halo.run/v1alpha1");
    }

    Mono<ServerResponse> connect(ServerRequest request) {
        return ServerResponse.temporaryRedirect(buildOauthRedirectUri(request))
            .build();
    }

    Mono<ServerResponse> disconnect(ServerRequest request) {
        String registrationId = request.pathVariable("registrationId");
        return userConnectionService.removeConnection(registrationId)
            .flatMap(result -> ServerResponse.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(result)
            );
    }

    URI buildOauthRedirectUri(ServerRequest request) {
        String registrationId = request.pathVariable("registrationId");
        Optional<String> redirectUri = request.queryParam("redirect_uri");
        return UriComponentsBuilder.fromPath("/oauth2/authorization/{registrationId}")
            .uriVariables(Map.of("registrationId", registrationId))
            .queryParam(SocialServerOauth2AuthorizationRequestResolver.SOCIAL_CONNECTION,
                BooleanUtils.TRUE)
            .queryParamIfPresent("binding_redirect_uri", redirectUri)
            .build()
            .toUri();
    }
}
