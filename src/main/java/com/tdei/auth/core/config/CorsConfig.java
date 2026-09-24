package com.tdei.auth.core.config;

import org.springframework.context.annotation.Configuration;

@Configuration
public class CorsConfig {

    private final ApplicationProperties applicationProperties;

    public CorsConfig(ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

}
