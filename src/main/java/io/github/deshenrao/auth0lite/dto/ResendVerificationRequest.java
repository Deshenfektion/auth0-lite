package io.github.deshenrao.auth0lite.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ResendVerificationRequest(
        @NotBlank
        @Email
        String email
) {
}
