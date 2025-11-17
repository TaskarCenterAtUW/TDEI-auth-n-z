package com.tdei.auth.core.config.exception.handler.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.GATEWAY_TIMEOUT)
public class GatewayTimeoutException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public GatewayTimeoutException(String message) {
        super(message);
    }
}
