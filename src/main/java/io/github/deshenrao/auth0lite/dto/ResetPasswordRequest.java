package io.github.deshenrao.auth0lite.dto;

import io.github.deshenrao.auth0lite.validation.StrongPassword;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        @NotBlank
        String token,

        @NotBlank
        @Size(max = 128)
        @StrongPassword
        String newPassword
) {
}
