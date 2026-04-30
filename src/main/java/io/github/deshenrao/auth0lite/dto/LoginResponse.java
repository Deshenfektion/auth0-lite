package io.github.deshenrao.auth0lite.dto;

public record LoginResponse(String accessToken, String tokenType, long expiresInSeconds, UserResponse user) {
}
