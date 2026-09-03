package unit.auth.core.config;

import com.tdei.auth.core.config.KeycloakClientsParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("Unit")
class KeycloakClientsParserTest {

    @Test
    @DisplayName("When TDEI_KEYCLOAK_CLIENTS is JSON, Expect client map parsed")
    void parseJsonTest() {
        Map<String, String> clients = KeycloakClientsParser.parse(
                "{\"tdei-gateway\":\"secret-a\",\"tdei-portal\":\"secret-b\"}");

        assertThat(clients).hasSize(2);
        assertThat(clients.get("tdei-gateway")).isEqualTo("secret-a");
        assertThat(clients.get("tdei-portal")).isEqualTo("secret-b");
    }

    @Test
    @DisplayName("When TDEI_KEYCLOAK_CLIENTS is delimited, Expect client map parsed")
    void parseDelimitedTest() {
        Map<String, String> clients = KeycloakClientsParser.parse(
                "tdei-gateway:secret-a;tdei-portal:secret-b");

        assertThat(clients).hasSize(2);
        assertThat(clients.get("tdei-gateway")).isEqualTo("secret-a");
        assertThat(clients.get("tdei-portal")).isEqualTo("secret-b");
    }

    @Test
    @DisplayName("When TDEI_KEYCLOAK_CLIENTS secret contains colon, Expect full secret preserved")
    void parseSecretWithColonTest() {
        Map<String, String> clients = KeycloakClientsParser.parse("my-client:abc:def:ghi");

        assertThat(clients).containsEntry("my-client", "abc:def:ghi");
    }

    @Test
    @DisplayName("When TDEI_KEYCLOAK_CLIENTS uses pipe delimiter, Expect client map parsed")
    void parsePipeDelimitedTest() {
        Map<String, String> clients = KeycloakClientsParser.parse(
                "tdei-gateway:secret-a|tdei-portal:secret-b");

        assertThat(clients).containsEntry("tdei-gateway", "secret-a");
        assertThat(clients).containsEntry("tdei-portal", "secret-b");
    }

    @Test
    @DisplayName("When TDEI_KEYCLOAK_CLIENTS is invalid, Expect IllegalArgumentException")
    void parseInvalidTest() {
        assertThrows(IllegalArgumentException.class, () -> KeycloakClientsParser.parse("not-json"));
    }
}
