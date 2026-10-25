package com.flarefitness.backend.exception;

public class ActionConfirmationRequiredException extends RuntimeException {
    public ActionConfirmationRequiredException() {
        super("Thao tac nay can ma xac nhan rieng gui toi email hien tai da duoc xac minh.");
    }
}
