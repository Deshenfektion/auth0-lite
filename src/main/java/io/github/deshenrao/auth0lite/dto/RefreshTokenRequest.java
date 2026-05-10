package io.github.deshenrao.auth0lite.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RefreshTokenRequest(
        @NotBlank
        @Size(max = 512)
        String refreshToken
) {
}
