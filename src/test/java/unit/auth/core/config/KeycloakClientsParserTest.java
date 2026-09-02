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
    @DisplayName("When KEYCLOAK_AUTH_CLIENTS_CREDS is JSON, Expect client map parsed")
    void parseJsonTest() {
        Map<String, String> clients = KeycloakClientsParser.parse(
                "{\"tdei-gateway\":\"secret-a\",\"tdei-portal\":\"secret-b\"}");

        assertThat(clients).hasSize(2);
        assertThat(clients.get("tdei-gateway")).isEqualTo("secret-a");
        assertThat(clients.get("tdei-portal")).isEqualTo("secret-b");
    }

    @Test
    @DisplayName("When KEYCLOAK_AUTH_CLIENTS_CREDS is delimited, Expect client map parsed")
    void parseDelimitedTest() {
        Map<String, String> clients = KeycloakClientsParser.parse(
                "tdei-gateway:secret-a;tdei-portal:secret-b");

        assertThat(clients).hasSize(2);
        assertThat(clients.get("tdei-gateway")).isEqualTo("secret-a");
        assertThat(clients.get("tdei-portal")).isEqualTo("secret-b");
    }

    @Test
    @DisplayName("When KEYCLOAK_AUTH_CLIENTS_CREDS secret contains colon, Expect full secret preserved")
    void parseSecretWithColonTest() {
        Map<String, String> clients = KeycloakClientsParser.parse("my-client:abc:def:ghi");

        assertThat(clients).containsEntry("my-client", "abc:def:ghi");
    }

    @Test
    @DisplayName("When KEYCLOAK_AUTH_CLIENTS_CREDS is invalid, Expect IllegalArgumentException")
    void parseInvalidTest() {
        assertThrows(IllegalArgumentException.class, () -> KeycloakClientsParser.parse("not-json"));
    }
}
