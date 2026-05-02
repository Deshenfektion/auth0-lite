package io.github.deshenrao.auth0lite.exception;

import org.springframework.http.HttpStatus;

public class RefreshTokenReuseDetectedException extends ApiException {

    public RefreshTokenReuseDetectedException() {
        super(HttpStatus.UNAUTHORIZED, "This refresh token has already been used. All sessions from this login "
                + "have been signed out for your security. Please log in again.");
    }
}
