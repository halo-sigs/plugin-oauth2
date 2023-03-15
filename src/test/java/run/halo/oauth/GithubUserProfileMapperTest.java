package run.halo.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Tests for {@link GithubUserProfileMapper}.
 *
 * @author guqing
 * @since 2.0.0
 */
class GithubUserProfileMapperTest {

    private GithubUserProfileMapper mapper;

    @BeforeEach
    public void setup() {
        mapper = new GithubUserProfileMapper();
    }

    @Test
    void mapProfile() {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("name", "testDisplayName");
        attributes.put("login", "testUsername");
        attributes.put("avatar_url", "testAvatarUrl");
        attributes.put("html_url", "testProfileUrl");
        OAuth2User oauth2User = new DefaultOAuth2User(Collections.emptySet(), attributes, "login");

        // 调用被测试的方法
        Oauth2UserProfile result = mapper.mapProfile(oauth2User);


        // 验证方法的行为和结果是否符合预期
        assertThat(result.getDisplayName()).isEqualTo("testDisplayName");
        assertThat(result.getUsername()).isEqualTo("testUsername");
        assertThat(result.getAvatarUrl()).isEqualTo("testAvatarUrl");
        assertThat(result.getProfileUrl()).isEqualTo("testProfileUrl");
    }

    @Test
    public void testSupports() {
        boolean result = mapper.supports("github");

        assertThat(result).isTrue();
    }

    @Test
    public void testSupportsWithEmptyRegistrationId() {
        assertThatThrownBy(() -> {
            mapper.supports("");
        }).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Registration id must not be blank");
    }
}
