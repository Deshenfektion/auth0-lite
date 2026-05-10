package io.github.deshenrao.auth0lite.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Set<String> RATE_LIMITED_PATHS = Set.of(
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/api/v1/account/verify-email",
            "/api/v1/account/resend-verification",
            "/api/v1/account/forgot-password",
            "/api/v1/account/reset-password"
    );

    private final RateLimiter rateLimiter;
    private final ObjectMapper objectMapper;

    public RateLimitingFilter(RateLimiter rateLimiter, ObjectMapper objectMapper) {
        this.rateLimiter = rateLimiter;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if (RATE_LIMITED_PATHS.contains(request.getRequestURI())) {
            String key = request.getRequestURI() + "|" + request.getRemoteAddr();
            if (!rateLimiter.tryConsume(key)) {
                writeTooManyRequests(response, rateLimiter.secondsUntilNextToken(key));
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private void writeTooManyRequests(HttpServletResponse response, long retryAfterSeconds) throws IOException {
        ProblemDetail problemDetail = ProblemDetail.forStatus(HttpStatus.TOO_MANY_REQUESTS);
        problemDetail.setTitle(HttpStatus.TOO_MANY_REQUESTS.getReasonPhrase());
        problemDetail.setDetail("Too many requests. Please try again later.");

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader(HttpHeaders.RETRY_AFTER, String.valueOf(Math.max(retryAfterSeconds, 1)));
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), problemDetail);
    }
}
