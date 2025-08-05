package run.halo.oauth;

import jakarta.validation.Valid;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.util.StringUtils;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import org.springframework.validation.annotation.Validated;

@Data
@ConfigurationProperties("oauth2")
@Validated
public class OAuth2Properties implements Validator {

    @Valid
    @NestedConfigurationProperty
    private final Proxy proxy = new Proxy();

    @Override
    public boolean supports(Class<?> clazz) {
        return OAuth2Properties.class == clazz;
    }

    @Override
    public void validate(Object target, Errors errors) {
        var properties = (OAuth2Properties) target;
        var p = properties.getProxy();
        if (p.isEnabled()) {
            if (p.getPort() <= 0 || p.getPort() > 65535) {
                errors.rejectValue("proxy.port", "Invalid port number",
                    "Port must be between 1 and 65535");
            }
            if (!StringUtils.hasText(p.getHost())) {
                errors.rejectValue("proxy.host", "Host cannot be blank when proxy is enabled");
            }
            if (p.getConnectTimeoutMillis() != null && p.getConnectTimeoutMillis() <= 0) {
                errors.rejectValue("proxy.connectTimeoutMillis",
                    "Connect timeout must be greater than zero");
            }
        }
    }

    @Data
    public static class Proxy {

        /**
         * Whether to enable the proxy.
         */
        private boolean enabled;

        /**
         * The host of the proxy server.
         */
        private String host;

        /**
         * The port of the proxy server.
         */
        private int port;

        /**
         * The username for the proxy server.
         */
        private String username;

        /**
         * The password for the proxy server.
         */
        private String password;

        /**
         * The connection timeout in milliseconds.
         */
        private Long connectTimeoutMillis;

    }
}
