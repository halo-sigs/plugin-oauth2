package run.halo.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.util.unit.DataSize;
import org.springframework.validation.BeanPropertyBindingResult;

class OAuth2PropertiesTest {

    @Test
    void shouldUse32KibAsDefaultMaxResponseHeaderSize() {
        var properties = new OAuth2Properties();
        assertThat(properties.getMaxResponseHeaderSize()).isEqualTo(DataSize.ofKilobytes(32));
        assertThat(validate(properties).hasErrors()).isFalse();
    }

    @Test
    void shouldRejectNonPositiveMaxResponseHeaderSize() {
        var properties = new OAuth2Properties();
        properties.setMaxResponseHeaderSize(DataSize.ofBytes(0));
        var errors = validate(properties);
        assertThat(errors.hasFieldErrors("maxResponseHeaderSize")).isTrue();
    }

    @Test
    void shouldApplyMaxResponseHeaderSizeToHttpClient() {
        var properties = new OAuth2Properties();
        properties.setMaxResponseHeaderSize(DataSize.ofKilobytes(64));
        var client = HaloOAuth2AuthenticationWebFilter.createHttpClient(properties);
        assertThat(client.configuration().decoder().maxHeaderSize()).isEqualTo(64 * 1024);
    }

    private static BeanPropertyBindingResult validate(OAuth2Properties properties) {
        var errors = new BeanPropertyBindingResult(properties, "oauth2");
        properties.validate(properties, errors);
        return errors;
    }
}
