package run.halo.oauth;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;
import run.halo.app.core.extension.endpoint.CustomEndpoint;
import run.halo.app.core.extension.endpoint.CustomEndpointsBuilder;
import run.halo.app.core.extension.service.DefaultRoleService;
import run.halo.app.core.extension.service.RoleService;
import run.halo.app.extension.ReactiveExtensionClient;

/**
 * @author guqing
 * @since 2.0.0
 */
@Configuration
public class OauthGithubConfig {

    @Bean
    RoleService roleService(ReactiveExtensionClient client) {
        return new DefaultRoleService(client);
    }

    @Bean
    RouterFunction<ServerResponse> oauthGithubRouter(ApplicationContext applicationContext) {
        CustomEndpointsBuilder builder = new CustomEndpointsBuilder();
        applicationContext.getBeanProvider(CustomEndpoint.class)
            .orderedStream()
            .forEach(builder::add);
        return builder.build();
    }
}
