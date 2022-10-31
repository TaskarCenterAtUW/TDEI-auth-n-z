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
    private keycloakProperties keycloak;
    private KeycloakEndpointUrls keycloakClientEndpoints;
    private String appname;

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
        //private String userUrl;
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
        private String userUrl;
    }
}

