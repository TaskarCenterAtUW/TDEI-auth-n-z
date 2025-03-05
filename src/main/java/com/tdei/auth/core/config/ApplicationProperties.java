package com.tdei.auth.core.config;

import lombok.Data;
import lombok.NoArgsConstructor;
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
        private String resource;
        private KeycloakCreds credentials;

        @Data
        @NoArgsConstructor
        public static class KeycloakCreds {
            private String secret = "";
        }
    }

    @Data
    @NoArgsConstructor
    public static class KeycloakEndpointUrls {
        private String baseUrl;
        private String redirectUrl;
    }
}

