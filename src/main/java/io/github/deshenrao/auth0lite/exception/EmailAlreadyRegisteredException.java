package io.github.deshenrao.auth0lite.exception;

import org.springframework.http.HttpStatus;

public class EmailAlreadyRegisteredException extends ApiException {

    public EmailAlreadyRegisteredException(String email) {
        super(HttpStatus.CONFLICT, "An account with email '%s' already exists".formatted(email));
    }
}
