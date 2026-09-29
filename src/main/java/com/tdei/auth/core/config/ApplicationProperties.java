package com.tdei.auth.core.config;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties
@Component
@Data
public class ApplicationProperties {
    private SwaggerProperties swagger;
    private SpringProperties spring;
    private keycloakProperties keycloak;
    private KeycloakEndpointUrls keycloakClientEndpoints;
    private SsoProperties sso = new SsoProperties();

    @Data
    @NoArgsConstructor
    public static class SpringProperties {
        private Application application;

        @Data
        @NoArgsConstructor
        public static class Application {
            private String secret;
            private int secretTtl;
            private String name;
            private List<String> allowedAppClients;
        }
    }

    @Data
    @NoArgsConstructor
    public static class SwaggerProperties {
        private SwaggerContact contact;
        private String title;
        private String description;
        private String version;

        @Data
        @NoArgsConstructor
        public static class SwaggerContact {
            private String name = "";
            private String email = "";
            private String url = "";
        }
    }


    @Data
    @NoArgsConstructor
    public static class keycloakProperties {
        private String authServerUrl;
        private int connectionPoolSize;
        private int connectionTimeout;
        private String realm;
    }

    @Data
    @NoArgsConstructor
    public static class KeycloakEndpointUrls {
        private String baseUrl;
        private String redirectUrl;
    }

    @Data
    @NoArgsConstructor
    public static class SsoProperties {
        private int stateTtlSeconds = 600;
        private List<String> allowedCorsOrigins = new ArrayList<>();
    }
}

