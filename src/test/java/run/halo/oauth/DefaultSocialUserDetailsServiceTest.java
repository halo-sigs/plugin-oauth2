package run.halo.oauth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Comparator;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import run.halo.app.core.extension.UserConnection;
import run.halo.app.extension.ReactiveExtensionClient;

/**
 * Tests for {@link DefaultSocialUserDetailsService}.
 *
 * @author guqing
 * @since 2.0.0
 */
@ExtendWith(MockitoExtension.class)
class DefaultSocialUserDetailsServiceTest {
    @Mock
    private ReactiveExtensionClient client;

    @Mock
    private ReactiveUserDetailsService userDetailsService;

    @InjectMocks
    private DefaultSocialUserDetailsService service;

    @Test
    @SuppressWarnings("unchecked")
    void loadUserByUserId() {
        // 创建测试数据
        String registrationId = "testRegistrationId";
        String principalName = "testPrincipalName";
        UserConnection userConnection = new UserConnection();
        UserConnection.UserConnectionSpec spec = new UserConnection.UserConnectionSpec();
        spec.setRegistrationId(registrationId);
        spec.setProviderUserId(principalName);
        spec.setUsername("testUsername");
        userConnection.setSpec(spec);
        UserDetails userDetails = new User("testUsername", "testPassword", Collections.emptyList());

        when(client.list(eq(UserConnection.class), any(Predicate.class), any(Comparator.class)))
            .thenReturn(Flux.just(userConnection));
        when(userDetailsService.findByUsername(eq("testUsername"))).thenReturn(
            Mono.just(userDetails));

        Mono<UserDetails> result = service.loadUserByUserId(registrationId, principalName);

        // 验证方法的行为和结果是否符合预期
        StepVerifier.create(result)
            .expectNext(userDetails)
            .verifyComplete();
        verify(client).list(eq(UserConnection.class), any(Predicate.class), any(Comparator.class));
        verify(userDetailsService).findByUsername(eq("testUsername"));
    }
}
