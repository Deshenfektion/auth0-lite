package io.github.deshenrao.auth0lite.controller;

import io.github.deshenrao.auth0lite.domain.JwtPrincipal;
import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.dto.SessionResponse;
import io.github.deshenrao.auth0lite.mapper.SessionMapper;
import io.github.deshenrao.auth0lite.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/sessions")
public class SessionController {

    private final SessionService sessionService;
    private final SessionMapper sessionMapper;

    public SessionController(SessionService sessionService, SessionMapper sessionMapper) {
        this.sessionService = sessionService;
        this.sessionMapper = sessionMapper;
    }

    @GetMapping
    public ResponseEntity<List<SessionResponse>> listSessions(@AuthenticationPrincipal JwtPrincipal principal) {
        List<SessionResponse> response = sessionService.listActiveSessions(principal.userId()).stream()
                .map(session -> sessionMapper.toResponse(session, principal.sessionId()))
                .toList();
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{sessionId}")
    public ResponseEntity<Void> revokeSession(
            @PathVariable UUID sessionId,
            @AuthenticationPrincipal JwtPrincipal principal,
            HttpServletRequest servletRequest
    ) {
        sessionService.revokeSession(sessionId, principal.userId(), requestMetadata(servletRequest));
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping
    public ResponseEntity<Void> revokeAllSessions(
            @AuthenticationPrincipal JwtPrincipal principal,
            HttpServletRequest servletRequest
    ) {
        sessionService.revokeAllSessions(principal.userId(), requestMetadata(servletRequest));
        return ResponseEntity.noContent().build();
    }

    private RequestMetadata requestMetadata(HttpServletRequest servletRequest) {
        return new RequestMetadata(
                servletRequest.getRemoteAddr(),
                servletRequest.getHeader(HttpHeaders.USER_AGENT)
        );
    }
}
