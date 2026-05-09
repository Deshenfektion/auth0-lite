package io.github.deshenrao.auth0lite.controller;

import io.github.deshenrao.auth0lite.domain.JwtPrincipal;
import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.dto.ChangePasswordRequest;
import io.github.deshenrao.auth0lite.dto.ForgotPasswordRequest;
import io.github.deshenrao.auth0lite.dto.ResendVerificationRequest;
import io.github.deshenrao.auth0lite.dto.ResetPasswordRequest;
import io.github.deshenrao.auth0lite.dto.VerifyEmailRequest;
import io.github.deshenrao.auth0lite.service.ChangePasswordService;
import io.github.deshenrao.auth0lite.service.EmailVerificationService;
import io.github.deshenrao.auth0lite.service.PasswordResetService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/account")
public class AccountController {

    private final EmailVerificationService emailVerificationService;
    private final PasswordResetService passwordResetService;
    private final ChangePasswordService changePasswordService;

    public AccountController(
            EmailVerificationService emailVerificationService,
            PasswordResetService passwordResetService,
            ChangePasswordService changePasswordService
    ) {
        this.emailVerificationService = emailVerificationService;
        this.passwordResetService = passwordResetService;
        this.changePasswordService = changePasswordService;
    }

    @PostMapping("/verify-email")
    public ResponseEntity<Void> verifyEmail(
            @Valid @RequestBody VerifyEmailRequest request,
            HttpServletRequest servletRequest
    ) {
        emailVerificationService.verifyEmail(request.token(), requestMetadata(servletRequest));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<Void> resendVerification(@Valid @RequestBody ResendVerificationRequest request) {
        emailVerificationService.resendVerificationEmail(request.email());
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        passwordResetService.requestPasswordReset(request.email());
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest servletRequest
    ) {
        passwordResetService.resetPassword(request.token(), request.newPassword(), requestMetadata(servletRequest));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            @AuthenticationPrincipal JwtPrincipal principal,
            HttpServletRequest servletRequest
    ) {
        changePasswordService.changePassword(
                principal.userId(),
                principal.sessionId(),
                request.currentPassword(),
                request.newPassword(),
                requestMetadata(servletRequest)
        );
        return ResponseEntity.noContent().build();
    }

    private RequestMetadata requestMetadata(HttpServletRequest servletRequest) {
        return new RequestMetadata(
                servletRequest.getRemoteAddr(),
                servletRequest.getHeader(HttpHeaders.USER_AGENT)
        );
    }
}
