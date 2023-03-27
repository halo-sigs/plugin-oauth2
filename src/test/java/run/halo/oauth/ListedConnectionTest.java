package run.halo.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link ListedConnection}.
 *
 * @author guqing
 * @since 2.0.0
 */
class ListedConnectionTest {

    @Test
    public void testBuilder() {
        // 创建测试数据
        ListedConnection.SimpleAuthProvider authProvider =
            ListedConnection.SimpleAuthProvider.builder()
                .displayName("testDisplayName")
                .logo("testLogo")
                .website("testWebsite")
                .authenticationUrl("testAuthenticationUrl")
                .helpPage("testHelpPage")
                .build();

        ListedConnection connection = ListedConnection.builder()
            .registrationId("testRegistrationId")
            .username("testUsername")
            .displayName("testDisplayName")
            .profileUrl("testProfileUrl")
            .avatarUrl("testAvatarUrl")
            .provider(authProvider)
            .build();

        // 验证对象的属性是否符合预期
        assertThat(connection.getRegistrationId()).isEqualTo("testRegistrationId");
        assertThat(connection.getUsername()).isEqualTo("testUsername");
        assertThat(connection.getDisplayName()).isEqualTo("testDisplayName");
        assertThat(connection.getProfileUrl()).isEqualTo("testProfileUrl");
        assertThat(connection.getAvatarUrl()).isEqualTo("testAvatarUrl");
        assertThat(connection.getProvider().getDisplayName()).isEqualTo("testDisplayName");
        assertThat(connection.getProvider().getLogo()).isEqualTo("testLogo");
        assertThat(connection.getProvider().getWebsite()).isEqualTo("testWebsite");
        assertThat(connection.getProvider().getAuthenticationUrl()).isEqualTo(
            "testAuthenticationUrl");
        assertThat(connection.getProvider().getHelpPage()).isEqualTo("testHelpPage");
    }

    @Test
    public void testValue() {
        // 创建测试数据
        ListedConnection.SimpleAuthProvider authProvider =
            new ListedConnection.SimpleAuthProvider("testDisplayName",
                "testLogo", "testWebsite", "testAuthenticationUrl", "testHelpPage");

        ListedConnection connection =
            new ListedConnection("testRegistrationId", "testUsername", "testDisplayName",
                "testProfileUrl", "testAvatarUrl", authProvider);

        // 验证对象的属性是否符合预期
        assertThat(connection.getRegistrationId()).isEqualTo("testRegistrationId");
        assertThat(connection.getUsername()).isEqualTo("testUsername");
        assertThat(connection.getDisplayName()).isEqualTo("testDisplayName");
        assertThat(connection.getProfileUrl()).isEqualTo("testProfileUrl");
        assertThat(connection.getAvatarUrl()).isEqualTo("testAvatarUrl");
        assertThat(connection.getProvider().getDisplayName()).isEqualTo("testDisplayName");
        assertThat(connection.getProvider().getLogo()).isEqualTo("testLogo");
        assertThat(connection.getProvider().getWebsite()).isEqualTo("testWebsite");
        assertThat(connection.getProvider().getAuthenticationUrl()).isEqualTo(
            "testAuthenticationUrl");
        assertThat(connection.getProvider().getHelpPage()).isEqualTo("testHelpPage");
    }
}
