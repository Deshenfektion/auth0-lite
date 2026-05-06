package io.github.deshenrao.auth0lite.controller;

import io.github.deshenrao.auth0lite.domain.RequestMetadata;
import io.github.deshenrao.auth0lite.dto.SessionResponse;
import io.github.deshenrao.auth0lite.mapper.SessionMapper;
import io.github.deshenrao.auth0lite.security.RequiresPermission;
import io.github.deshenrao.auth0lite.security.RequiresRole;
import io.github.deshenrao.auth0lite.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin/users/{userId}/sessions")
public class AdminSessionController {

    private final SessionService sessionService;
    private final SessionMapper sessionMapper;

    public AdminSessionController(SessionService sessionService, SessionMapper sessionMapper) {
        this.sessionService = sessionService;
        this.sessionMapper = sessionMapper;
    }

    @GetMapping
    @RequiresRole("ADMIN")
    public ResponseEntity<List<SessionResponse>> listSessions(@PathVariable UUID userId) {
        List<SessionResponse> response = sessionService.listActiveSessions(userId).stream()
                .map(session -> sessionMapper.toResponse(session, null))
                .toList();
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{sessionId}")
    @RequiresPermission("sessions:revoke:any")
    public ResponseEntity<Void> revokeSession(
            @PathVariable UUID userId,
            @PathVariable UUID sessionId,
            HttpServletRequest servletRequest
    ) {
        sessionService.adminRevokeSession(userId, sessionId, requestMetadata(servletRequest));
        return ResponseEntity.noContent().build();
    }

    private RequestMetadata requestMetadata(HttpServletRequest servletRequest) {
        return new RequestMetadata(
                servletRequest.getRemoteAddr(),
                servletRequest.getHeader(HttpHeaders.USER_AGENT)
        );
    }
}
