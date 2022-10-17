package com.tdei.auth.service;

import com.tdei.auth.model.keycloak.KUserInfo;
import feign.Feign;
import feign.Headers;
import feign.Param;
import feign.RequestLine;
import feign.form.FormEncoder;
import feign.gson.GsonDecoder;

//@Headers("Accept: application/json")
public interface KeyclockUserClient {
    static KeyclockUserClient connect(String baseUri) {
        return Feign.builder()
                .decoder(new GsonDecoder())
                .encoder(new FormEncoder())
                .target(KeyclockUserClient.class, baseUri);
    }

    @RequestLine("GET /")
    @Headers({"Content-Type: application/x-www-form-urlencoded", "Authorization: Bearer {token}"})
    KUserInfo userInfo(@Param("client_id") String clientId, @Param("client_secret") String clientSecret, @Param("token") String token);
}
