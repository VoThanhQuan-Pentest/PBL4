package com.flarefitness.backend.exception;

/** Stable public action outcomes; never includes OTP, model internals or credentials. */
public class PostloginActionException extends RuntimeException {
    public enum Kind { TEMP_HOLD, REQUEST_ID_REQUIRED, REQUEST_IN_PROGRESS, STALE_DECISION, REPLAY_REJECTED }
    private final Kind kind;
    private final String decisionId;
    private final Integer retryAfterSeconds;
    public PostloginActionException(Kind kind, String message, String decisionId, Integer retryAfterSeconds) {
        super(message);this.kind = kind;this.decisionId = decisionId;
        this.retryAfterSeconds = retryAfterSeconds == null ? null : Math.max(1, Math.min(600, retryAfterSeconds));
    }
    public int status() { return kind == Kind.TEMP_HOLD ? 429 : kind == Kind.REQUEST_IN_PROGRESS || kind == Kind.STALE_DECISION ? 409 : 400; }
    public String code() {
        return switch (kind) {
            case TEMP_HOLD -> "ACTION_TEMPORARILY_HELD";
            case REQUEST_ID_REQUIRED -> "POSTLOGIN_REQUEST_ID_REQUIRED";
            case REQUEST_IN_PROGRESS -> "POSTLOGIN_REQUEST_IN_PROGRESS";
            case STALE_DECISION -> "POSTLOGIN_DECISION_STALE";
            case REPLAY_REJECTED -> "POSTLOGIN_REQUEST_REJECTED";
        };
    }
    public String decisionId() { return decisionId; }
    public Integer retryAfterSeconds() { return retryAfterSeconds; }
}
