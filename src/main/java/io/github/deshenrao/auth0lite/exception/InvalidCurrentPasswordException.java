package io.github.deshenrao.auth0lite.exception;

import org.springframework.http.HttpStatus;

public class InvalidCurrentPasswordException extends ApiException {

    public InvalidCurrentPasswordException() {
        super(HttpStatus.UNAUTHORIZED, "Current password is incorrect");
    }
}
