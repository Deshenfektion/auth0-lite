package io.github.deshenrao.auth0lite.dto;

public record LoginResponse(TokenResponse tokens, UserResponse user) {
}
