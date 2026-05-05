package io.github.deshenrao.auth0lite.security;

import com.nimbusds.jwt.JWTClaimsSet;
import io.github.deshenrao.auth0lite.domain.JwtPrincipal;
import io.github.deshenrao.auth0lite.exception.InvalidTokenException;
import io.github.deshenrao.auth0lite.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.UUID;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String INVALID_TOKEN_REQUEST_ATTRIBUTE = "auth0lite.invalidTokenReason";

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String token = extractBearerToken(request);

        if (token != null) {
            try {
                JWTClaimsSet claims = jwtService.parseAndValidate(token);
                SecurityContextHolder.getContext().setAuthentication(buildAuthentication(claims));
            } catch (InvalidTokenException exception) {
                SecurityContextHolder.clearContext();
                request.setAttribute(INVALID_TOKEN_REQUEST_ATTRIBUTE, exception.getMessage());
            } catch (ParseException exception) {
                SecurityContextHolder.clearContext();
                request.setAttribute(INVALID_TOKEN_REQUEST_ATTRIBUTE, "Token claims are malformed");
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractBearerToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            return header.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    private Authentication buildAuthentication(JWTClaimsSet claims) throws ParseException {
        UUID userId = UUID.fromString(claims.getSubject());
        UUID sessionId = UUID.fromString(claims.getStringClaim("sid"));
        String email = claims.getStringClaim("email");
        List<String> roles = claims.getStringListClaim("roles");

        List<SimpleGrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .toList();

        JwtPrincipal principal = new JwtPrincipal(userId, sessionId, email);
        return new UsernamePasswordAuthenticationToken(principal, null, authorities);
    }
}
