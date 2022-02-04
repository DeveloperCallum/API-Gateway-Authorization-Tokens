package com.beamedcallum.gateway.authorization.tokens.jwt.exceptions;

import com.beamedcallum.gateway.tokens.exceptions.TokenException;

public class JWTParseException extends TokenException {
    public JWTParseException() {
    }

    public JWTParseException(String message) {
        super(message);
    }

    public JWTParseException(String message, Throwable cause) {
        super(message, cause);
    }

    public JWTParseException(Throwable cause) {
        super(cause);
    }

    public JWTParseException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
