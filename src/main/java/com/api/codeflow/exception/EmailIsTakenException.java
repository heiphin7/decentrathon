package com.api.codeflow.exception;

public class EmailIsTakenException extends Exception {
    public EmailIsTakenException(String message) {
        super(message);
    }
}
