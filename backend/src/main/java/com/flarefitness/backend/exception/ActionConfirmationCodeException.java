package com.flarefitness.backend.exception;

/** Retry the same immutable challenge; never create a new operation on a typo. */
public class ActionConfirmationCodeException extends BadRequestException {
    public ActionConfirmationCodeException() {
        super("Ma xac nhan khong dung, da dung hoac da het han.");
    }
}
