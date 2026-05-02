package io.github.deshenrao.auth0lite.controller;

import io.github.deshenrao.auth0lite.config.JwtProperties;
import io.github.deshenrao.auth0lite.domain.IssuedRefreshToken;
import io.github.deshenrao.auth0lite.domain.RefreshResult;
import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.dto.LoginRequest;
import io.github.deshenrao.auth0lite.dto.LoginResponse;
import io.github.deshenrao.auth0lite.dto.RefreshTokenRequest;
import io.github.deshenrao.auth0lite.dto.RegisterUserRequest;
import io.github.deshenrao.auth0lite.dto.TokenResponse;
import io.github.deshenrao.auth0lite.dto.UserResponse;
import io.github.deshenrao.auth0lite.entity.User;
import io.github.deshenrao.auth0lite.mapper.UserMapper;
import io.github.deshenrao.auth0lite.service.AuthenticationService;
import io.github.deshenrao.auth0lite.service.JwtService;
import io.github.deshenrao.auth0lite.service.RefreshTokenService;
import io.github.deshenrao.auth0lite.service.UserRegistrationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final UserRegistrationService userRegistrationService;
    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final UserMapper userMapper;

    public AuthController(
            UserRegistrationService userRegistrationService,
            AuthenticationService authenticationService,
            RefreshTokenService refreshTokenService,
            JwtService jwtService,
            JwtProperties jwtProperties,
            UserMapper userMapper
    ) {
        this.userRegistrationService = userRegistrationService;
        this.authenticationService = authenticationService;
        this.refreshTokenService = refreshTokenService;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
        this.userMapper = userMapper;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterUserRequest request) {
        User user = userRegistrationService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(userMapper.toResponse(user));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest servletRequest
    ) {
        User user = authenticationService.login(request, requestMetadata(servletRequest));

        String accessToken = jwtService.generateAccessToken(userMapper.toTokenSubject(user));
        IssuedRefreshToken refreshToken = refreshTokenService.issueForNewLogin(user.getId());

        LoginResponse response = new LoginResponse(
                tokenResponse(accessToken, refreshToken.rawToken()),
                userMapper.toResponse(user)
        );
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest servletRequest
    ) {
        RefreshResult result = refreshTokenService.rotate(request.refreshToken(), requestMetadata(servletRequest));
        String accessToken = jwtService.generateAccessToken(result.subject());

        return ResponseEntity.ok(tokenResponse(accessToken, result.refreshToken().rawToken()));
    }

    private TokenResponse tokenResponse(String accessToken, String refreshToken) {
        return new TokenResponse(accessToken, refreshToken, "Bearer", jwtProperties.accessTokenTtl().toSeconds());
    }

    private RequestMetadata requestMetadata(HttpServletRequest servletRequest) {
        return new RequestMetadata(
                servletRequest.getRemoteAddr(),
                servletRequest.getHeader(HttpHeaders.USER_AGENT)
        );
    }
}
