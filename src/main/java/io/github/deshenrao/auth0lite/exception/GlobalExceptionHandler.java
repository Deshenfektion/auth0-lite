package io.github.deshenrao.auth0lite.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Duration;
import java.time.Instant;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<ProblemDetail> handleAccountLocked(AccountLockedException exception) {
        ProblemDetail problemDetail = ProblemDetail.forStatus(HttpStatus.LOCKED);
        problemDetail.setTitle(HttpStatus.LOCKED.getReasonPhrase());
        problemDetail.setDetail(exception.getMessage());

        long retryAfterSeconds = Duration.between(Instant.now(), exception.getLockedUntil()).toSeconds();

        return ResponseEntity.status(HttpStatus.LOCKED)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(Math.max(retryAfterSeconds, 0)))
                .body(problemDetail);
    }

    @ExceptionHandler(ApiException.class)
    public ProblemDetail handleApiException(ApiException exception) {
        ProblemDetail problemDetail = ProblemDetail.forStatus(exception.getStatus());
        problemDetail.setTitle(exception.getStatus().getReasonPhrase());
        problemDetail.setDetail(exception.getMessage());
        return problemDetail;
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleUnexpectedException(Exception exception) {
        log.error("Unhandled exception reached the global fallback handler", exception);
        ProblemDetail problemDetail = ProblemDetail.forStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        problemDetail.setTitle("Internal Server Error");
        problemDetail.setDetail("An unexpected error occurred. Please try again later.");
        return problemDetail;
    }
}
