package run.halo.oauth;

import jakarta.validation.Valid;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.util.StringUtils;
import org.springframework.util.unit.DataSize;
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

    /**
     * The maximum size of response headers returned by OAuth2/OIDC providers.
     * Defaults to 32 KiB because some providers (e.g. GitHub) may exceed the default 8 KiB.
     */
    private DataSize maxResponseHeaderSize = DataSize.ofKilobytes(32);

    @Override
    public boolean supports(Class<?> clazz) {
        return OAuth2Properties.class == clazz;
    }

    @Override
    public void validate(Object target, Errors errors) {
        var properties = (OAuth2Properties) target;
        var maxResponseHeaderSize = properties.getMaxResponseHeaderSize();
        if (maxResponseHeaderSize == null || maxResponseHeaderSize.toBytes() <= 0
            || maxResponseHeaderSize.toBytes() > Integer.MAX_VALUE) {
            errors.rejectValue("maxResponseHeaderSize", "Invalid max response header size",
                "Max response header size must be greater than zero and less than 2 GiB");
        }
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
