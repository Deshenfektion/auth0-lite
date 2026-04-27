package io.github.deshenrao.auth0lite.controller;

import io.github.deshenrao.auth0lite.dto.RegisterUserRequest;
import io.github.deshenrao.auth0lite.dto.UserResponse;
import io.github.deshenrao.auth0lite.entity.User;
import io.github.deshenrao.auth0lite.mapper.UserMapper;
import io.github.deshenrao.auth0lite.service.UserRegistrationService;
import jakarta.validation.Valid;
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
    private final UserMapper userMapper;

    public AuthController(UserRegistrationService userRegistrationService, UserMapper userMapper) {
        this.userRegistrationService = userRegistrationService;
        this.userMapper = userMapper;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterUserRequest request) {
        User user = userRegistrationService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(userMapper.toResponse(user));
    }
}
