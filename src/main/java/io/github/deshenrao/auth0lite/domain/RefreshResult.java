package io.github.deshenrao.auth0lite.domain;

public record RefreshResult(TokenSubject subject, IssuedRefreshToken refreshToken) {
}
