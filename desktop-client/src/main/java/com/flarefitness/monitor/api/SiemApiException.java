package com.flarefitness.monitor.api;

public class SiemApiException extends RuntimeException {
    private final int statusCode;

    public SiemApiException(int statusCode, String message) {
        super(message);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
