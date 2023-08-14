package com.tdei.auth.integration;

import com.tdei.auth.core.config.ApplicationProperties;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UsersResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;

@Tag("Integration")
@RequiredArgsConstructor
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class authIntegrationTest {
    @Autowired
    TestRestTemplate restTemplate;
    @Autowired
    ApplicationProperties applicationProperties;
    @Autowired
    private Keycloak keycloakInstance;
    @LocalServerPort
    private int port;

    @Test
    @DisplayName("When requested for Keycloak health status, Expect to return HTTP Status 200")
    void validateKeycloakConnectivity() {

        String url = applicationProperties.getKeycloak().getAuthServerUrl() + "/health";
        var result = this.restTemplate.getForEntity(url, Object.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    @DisplayName("When requested for Keycloak user count, Expect to return HTTP Status 200 with >=0 count")
    void validateKeycloakUserCount() {

        UsersResource usersResource = keycloakInstance.realm(applicationProperties.getKeycloak().getRealm()).users();
        int userCount = usersResource.count();
        assertThat(userCount).isGreaterThanOrEqualTo(0);
    }
}
