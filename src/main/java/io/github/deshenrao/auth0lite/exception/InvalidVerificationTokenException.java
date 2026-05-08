package io.github.deshenrao.auth0lite.exception;

import org.springframework.http.HttpStatus;

public class InvalidVerificationTokenException extends ApiException {

    public InvalidVerificationTokenException() {
        super(HttpStatus.BAD_REQUEST, "This verification link is invalid or has expired");
    }
}
