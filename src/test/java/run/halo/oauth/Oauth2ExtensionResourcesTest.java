package run.halo.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

class Oauth2ExtensionResourcesTest {

    @Test
    void authProviderShouldContainLogtoProvider() throws IOException {
        var content = readResource("extensions/auth-provider.yaml");

        assertThat(content).contains("name: logto");
        assertThat(content).contains("displayName: Logto");
        assertThat(content).contains("authenticationUrl: /oauth2/authorization/logto");
        assertThat(content).contains("name: logto-oauth2-setting");
        assertThat(content).contains("group: logtoOauth");
        assertThat(content).contains("configMapRef:");
        assertThat(content).contains("name: oauth2-logto-config");
    }

    @Test
    void clientRegistrationsShouldContainLogtoRegistrationAndExplicitJwsAlgorithm()
        throws IOException {
        var content = readResource("extensions/client-registrations.yaml");

        assertThat(content).contains("name: logto");
        assertThat(content).contains("clientName: \"Logto\"");
        assertThat(content).contains("redirectUri: \"{baseUrl}/login/oauth2/code/logto\"");
        assertThat(content).contains("jwsAlgorithm: \"ES384\"");
        assertThat(content).doesNotContain("configurationMetadata:");
    }

    @Test
    void settingShouldContainDedicatedLogtoForm() throws IOException {
        var content = readResource("extensions/setting.yaml");

        assertThat(content).contains("name: logto-oauth2-setting");
        assertThat(content).contains("group: logtoOauth");
        assertThat(content).contains("name: endpoint");
        assertThat(content).contains("label: \"Endpoint\"");
        assertThat(content).doesNotContain("auth.srku.cn");
    }

    @Test
    void extensionResourcesShouldNotContainPrivateLogtoEndpointExample() throws IOException {
        assertThat(readResource("extensions/auth-provider.yaml")).doesNotContain("auth.srku.cn");
        assertThat(readResource("extensions/client-registrations.yaml")).doesNotContain("auth.srku.cn");
        assertThat(readResource("extensions/setting.yaml")).doesNotContain("auth.srku.cn");
    }

    private static String readResource(String path) throws IOException {
        try (var inputStream = new ClassPathResource(path).getInputStream()) {
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
