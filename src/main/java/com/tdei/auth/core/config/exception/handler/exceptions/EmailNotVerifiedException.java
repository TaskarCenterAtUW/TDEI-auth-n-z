package com.tdei.auth.core.config.exception.handler.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class EmailNotVerifiedException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public EmailNotVerifiedException(String message) {
        super(message);
    }
}
