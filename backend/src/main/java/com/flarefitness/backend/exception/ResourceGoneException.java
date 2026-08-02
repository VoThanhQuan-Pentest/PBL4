package com.flarefitness.backend.exception;

public class ResourceGoneException extends RuntimeException {

    public ResourceGoneException(String message) {
        super(message);
    }
}
