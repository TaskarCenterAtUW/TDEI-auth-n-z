package com.tdei.auth.service;

import com.tdei.auth.core.config.exception.handler.exceptions.InvalidSsoRequestException;
import org.springframework.stereotype.Component;

@Component
public class SsoRedirectValidator {

    public void validateRedirectUri(String redirectUri) {
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new InvalidSsoRequestException("redirect_uri is required");
        }
//        if (!redirectUri.startsWith("https://")) {
//            throw new InvalidSsoRequestException("redirect_uri must use https");
//        }
    }
}
