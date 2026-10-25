package com.flarefitness.backend.exception;

import java.time.OffsetDateTime;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(PostloginActionException.class)
    public ResponseEntity<ApiErrorResponse> handlePostloginAction(PostloginActionException exception) {
        HttpStatus status = HttpStatus.valueOf(exception.status());
        ApiErrorResponse base = build(status, exception.code(), exception.getMessage()).getBody();
        ApiErrorResponse body = new ApiErrorResponse(base.timestamp(), base.status(), base.error(), base.message(),
                base.code(), base.traceId(), exception.decisionId(), exception.retryAfterSeconds());
        var response = ResponseEntity.status(status);
        if (exception.retryAfterSeconds() != null) response.header("Retry-After", exception.retryAfterSeconds().toString());
        return response.body(body);
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleNotFound(ResourceNotFoundException exception) {
        return build(HttpStatus.NOT_FOUND, "RESOURCE_NOT_FOUND", exception.getMessage());
    }

    /** An unmatched route is client-side 404 telemetry, not an internal server failure. */
    @ExceptionHandler({NoResourceFoundException.class, NoHandlerFoundException.class})
    public ResponseEntity<ApiErrorResponse> handleMissingRoute(Exception exception) {
        // Framework exception messages include attacker-controlled paths; do not echo or log them.
        return build(HttpStatus.NOT_FOUND, "RESOURCE_NOT_FOUND", "Tai nguyen khong ton tai.");
    }

    @ExceptionHandler(ResourceGoneException.class)
    public ResponseEntity<ApiErrorResponse> handleGone(ResourceGoneException exception) {
        return build(HttpStatus.GONE, "RESOURCE_GONE", exception.getMessage());
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ApiErrorResponse> handleBadRequest(BadRequestException exception) {
        return build(HttpStatus.BAD_REQUEST, "BAD_REQUEST", exception.getMessage());
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ApiErrorResponse> handleUnauthorized(UnauthorizedException exception) {
        return build(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", exception.getMessage());
    }

    @ExceptionHandler(TooManyRequestsException.class)
    public ResponseEntity<ApiErrorResponse> handleTooManyRequests(TooManyRequestsException exception) {
        return build(HttpStatus.TOO_MANY_REQUESTS, "RATE_LIMITED", exception.getMessage());
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ApiErrorResponse> handleConflict(ConflictException exception) {
        return build(HttpStatus.CONFLICT, "CONFLICT", exception.getMessage());
    }

    @ExceptionHandler(ActionConfirmationRequiredException.class)
    public ResponseEntity<ApiErrorResponse> handleActionConfirmationRequired(ActionConfirmationRequiredException exception) {
        return build(HttpStatus.CONFLICT, "ACTION_CONFIRMATION_REQUIRED", exception.getMessage());
    }

    @ExceptionHandler(ActionConfirmationCodeException.class)
    public ResponseEntity<ApiErrorResponse> handleActionConfirmationCode(ActionConfirmationCodeException exception) {
        return build(HttpStatus.BAD_REQUEST, "ACTION_CONFIRMATION_CODE_INVALID", exception.getMessage());
    }

    @ExceptionHandler(ServiceUnavailableException.class)
    public ResponseEntity<ApiErrorResponse> handleServiceUnavailable(ServiceUnavailableException exception) {
        return build(HttpStatus.SERVICE_UNAVAILABLE, "SIEM_UNAVAILABLE", exception.getMessage());
    }

    @ExceptionHandler(ObjectOptimisticLockingFailureException.class)
    public ResponseEntity<ApiErrorResponse> handleOptimisticLock(ObjectOptimisticLockingFailureException exception) {
        return build(HttpStatus.CONFLICT, "STALE_VERSION", "Du lieu da duoc cap nhat boi mot phien khac. Hay tai lai.");
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccessDenied(AccessDeniedException exception) {
        return build(HttpStatus.FORBIDDEN, "FORBIDDEN", "Ban khong co quyen truy cap tai nguyen nay.");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleValidation(MethodArgumentNotValidException exception) {
        String message = exception.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(this::formatFieldError)
                .collect(Collectors.joining("; "));
        return build(HttpStatus.BAD_REQUEST, "VALIDATION_FAILED", message);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiErrorResponse> handleUnreadableMessage(HttpMessageNotReadableException exception) {
        return build(HttpStatus.BAD_REQUEST, "MALFORMED_REQUEST", "Du lieu gui len khong hop le.");
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiErrorResponse> handleArgumentTypeMismatch(
            MethodArgumentTypeMismatchException exception) {
        return build(HttpStatus.BAD_REQUEST, "INVALID_PARAMETER", "Tham so API khong hop le.");
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ApiErrorResponse> handleMissingParameter(MissingServletRequestParameterException exception) {
        return build(HttpStatus.BAD_REQUEST, "MISSING_PARAMETER", "Thieu tham so API bat buoc.");
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiErrorResponse> handleMethodNotSupported(HttpRequestMethodNotSupportedException exception) {
        return build(HttpStatus.METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED", "Phuong thuc API khong duoc ho tro.");
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiErrorResponse> handleDataIntegrity(DataIntegrityViolationException exception) {
        LOGGER.warn(
                "Database constraint rejected the request; causeType={} traceId={}",
                mostSpecificCauseType(exception),
                currentTraceId());
        return build(HttpStatus.BAD_REQUEST, "DATA_CONSTRAINT_VIOLATION", "Du lieu khong hop le voi rang buoc database.");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleUnexpected(Exception exception) {
        LOGGER.error("Unexpected API error", exception);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Da xay ra loi noi bo.");
    }

    private String formatFieldError(FieldError fieldError) {
        return fieldError.getField() + ": " + fieldError.getDefaultMessage();
    }

    private ResponseEntity<ApiErrorResponse> build(HttpStatus status, String code, String message) {
        String traceId = currentTraceId();
        return ResponseEntity.status(status)
                .body(new ApiErrorResponse(
                        OffsetDateTime.now(),
                        status.value(),
                        status.getReasonPhrase(),
                        message,
                        code,
                        traceId));
    }

    private static String currentTraceId() {
        String traceId = MDC.get("traceId");
        return traceId == null ? "" : traceId;
    }

    private static String mostSpecificCauseType(DataIntegrityViolationException exception) {
        Throwable cause = exception.getMostSpecificCause();
        return cause.getClass().getSimpleName();
    }
}
