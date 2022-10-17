package com.tdei.auth;

import com.microsoft.applicationinsights.attach.ApplicationInsights;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
@Slf4j
public class TdeiAuthApplication {

    public static void main(String[] args) {

        ApplicationInsights.attach();
        SpringApplication.run(TdeiAuthApplication.class, args);
        log.info("TDEI Auth API Started Successfully !");
    }
}
