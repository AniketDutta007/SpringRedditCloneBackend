package com.example.springredditclone.exception;

public class UsernameAlreadyExistException extends Exception {
    private static final String message = "Username already exist";

    public UsernameAlreadyExistException() {
        super(message);
    }
}
