package run.halo.oauth;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;
import run.halo.app.core.extension.endpoint.CustomEndpoint;
import run.halo.app.core.extension.endpoint.CustomEndpointsBuilder;

/**
 * @author guqing
 * @since 2.0.0
 */
@Configuration
public class OauthGithubConfig {

    @Bean
    RouterFunction<ServerResponse> oauthGithubRouter(ApplicationContext applicationContext) {
        CustomEndpointsBuilder builder = new CustomEndpointsBuilder();
        applicationContext.getBeanProvider(CustomEndpoint.class)
            .orderedStream()
            .forEach(builder::add);
        return builder.build();
    }
}
