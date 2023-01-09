package com.tdei.auth.service;

import com.google.gson.internal.LinkedTreeMap;
import feign.*;
import feign.form.FormEncoder;
import feign.gson.GsonDecoder;
import feign.slf4j.Slf4jLogger;

public interface KeyclockTokenClient {
    static KeyclockTokenClient connect(String baseUri) {
        return Feign.builder()
                .logger(new Slf4jLogger(KeyclockTokenClient.class))
                .logLevel(Logger.Level.FULL)
                .decoder(new GsonDecoder())
                .encoder(new FormEncoder())
                .target(KeyclockTokenClient.class, baseUri);
    }

    @RequestLine("POST /")
    @Headers({"Content-Type: application/x-www-form-urlencoded"})
    LinkedTreeMap refreshToken(@Param("client_id") String clientId, @Param("client_secret") String clientSecret, @Param("refresh_token") String token, @Param("grant_type") String grantType);
}
