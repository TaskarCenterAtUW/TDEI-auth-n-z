package unit.auth.service;

import com.tdei.auth.core.config.exception.handler.exceptions.InvalidSsoRequestException;
import com.tdei.auth.service.SsoRedirectValidator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("Unit")
class SsoRedirectValidatorTest {

    private final SsoRedirectValidator validator = new SsoRedirectValidator();

    @Test
    @DisplayName("When redirect_uri is valid https URL, Expect no exception")
    void validateRedirectUriSuccess() {
        assertDoesNotThrow(() -> validator.validateRedirectUri("https://portal.tdei.us/login"));
    }

    @Test
    @DisplayName("When redirect_uri is blank, Expect InvalidSsoRequestException")
    void validateRedirectUriBlank() {
        assertThrows(InvalidSsoRequestException.class, () -> validator.validateRedirectUri(" "));
    }

    @Test
    @DisplayName("When redirect_uri is http URL, Expect no exception")
    void validateRedirectUriHttp() {
        assertDoesNotThrow(() -> validator.validateRedirectUri("http://portal.tdei.us/login"));
    }
}
