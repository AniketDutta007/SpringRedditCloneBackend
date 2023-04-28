package com.example.springredditclone.exception;

public class EmailAlreadyExistException extends Exception {
    private static final String message = "Email already exist";

    public EmailAlreadyExistException() {
        super(message);
    }
}
