package io.github.deshenrao.auth0lite.exception;

import org.springframework.http.HttpStatus;

public class InvalidPasswordResetTokenException extends ApiException {

    public InvalidPasswordResetTokenException() {
        super(HttpStatus.BAD_REQUEST, "This password reset link is invalid or has expired");
    }
}
