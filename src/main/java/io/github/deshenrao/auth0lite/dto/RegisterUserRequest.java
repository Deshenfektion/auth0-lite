package io.github.deshenrao.auth0lite.dto;

import io.github.deshenrao.auth0lite.validation.StrongPassword;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterUserRequest(
        @NotBlank
        @Email
        @Size(max = 255)
        String email,

        @NotBlank
        @StrongPassword
        String password
) {
}
