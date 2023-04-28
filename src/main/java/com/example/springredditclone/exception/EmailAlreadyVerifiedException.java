package com.example.springredditclone.exception;

public class EmailAlreadyVerifiedException extends Exception {
    private static final String message = "Email already verified";

    public EmailAlreadyVerifiedException() {
        super(message);
    }
}
