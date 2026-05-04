package io.github.deshenrao.auth0lite.exception;

import org.springframework.http.HttpStatus;

public class SessionNotFoundException extends ApiException {

    public SessionNotFoundException() {
        super(HttpStatus.NOT_FOUND, "Session not found");
    }
}
