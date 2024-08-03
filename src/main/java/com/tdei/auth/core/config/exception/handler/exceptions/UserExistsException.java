package com.tdei.auth.core.config.exception.handler.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class UserExistsException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public UserExistsException(String message) {
        super(message);
    }
}
