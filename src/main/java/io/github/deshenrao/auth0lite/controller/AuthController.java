package io.github.deshenrao.auth0lite.controller;

import io.github.deshenrao.auth0lite.config.JwtProperties;
import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.dto.LoginRequest;
import io.github.deshenrao.auth0lite.dto.LoginResponse;
import io.github.deshenrao.auth0lite.dto.RegisterUserRequest;
import io.github.deshenrao.auth0lite.dto.UserResponse;
import io.github.deshenrao.auth0lite.entity.User;
import io.github.deshenrao.auth0lite.mapper.UserMapper;
import io.github.deshenrao.auth0lite.service.AuthenticationService;
import io.github.deshenrao.auth0lite.service.JwtService;
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
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final UserMapper userMapper;

    public AuthController(
            UserRegistrationService userRegistrationService,
            AuthenticationService authenticationService,
            JwtService jwtService,
            JwtProperties jwtProperties,
            UserMapper userMapper
    ) {
        this.userRegistrationService = userRegistrationService;
        this.authenticationService = authenticationService;
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
        RequestMetadata metadata = new RequestMetadata(
                servletRequest.getRemoteAddr(),
                servletRequest.getHeader(HttpHeaders.USER_AGENT)
        );
        User user = authenticationService.login(request, metadata);
        String accessToken = jwtService.generateAccessToken(userMapper.toTokenSubject(user));

        LoginResponse response = new LoginResponse(
                accessToken,
                "Bearer",
                jwtProperties.accessTokenTtl().toSeconds(),
                userMapper.toResponse(user)
        );
        return ResponseEntity.ok(response);
    }
}
