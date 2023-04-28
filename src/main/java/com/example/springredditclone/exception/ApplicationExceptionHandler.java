package com.example.springredditclone.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class ApplicationExceptionHandler {

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(InvalidTokenException.class)
    public Map<String, String> handleInvalidTokenException(InvalidTokenException exp) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("success", "false");
        errorMap.put("message", exp.getMessage());
        return errorMap;
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(EmailAlreadyVerifiedException.class)
    public Map<String, String> handleEmailAlreadyVerifiedException(EmailAlreadyVerifiedException exp) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("success", "false");
        errorMap.put("message", exp.getMessage());
        return errorMap;
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(SubredditNotFoundException.class)
    public Map<String, String> handleSubredditNotFoundException(SubredditNotFoundException exp) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("success", "false");
        errorMap.put("message", exp.getMessage());
        return errorMap;
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(UsernameAlreadyExistException.class)
    public Map<String, String> handleUsernameAlreadyExistException(UsernameAlreadyExistException exp) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("success", "false");
        errorMap.put("message", exp.getMessage());
        return errorMap;
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(EmailAlreadyExistException.class)
    public Map<String, String> handleEmailAlreadyExistException(EmailAlreadyExistException exp) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("success", "false");
        errorMap.put("message", exp.getMessage());
        return errorMap;
    }

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(UserNotFoundException.class)
    public Map<String, String> handleUserNotFoundException(UserNotFoundException exp) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("success", "false");
        errorMap.put("message", exp.getMessage());
        return errorMap;
    }

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(PostNotFoundException.class)
    public Map<String, String> handlePostNotFoundException(PostNotFoundException exp) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("success", "false");
        errorMap.put("message", exp.getMessage());
        return errorMap;
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(InvalidCredentialsException.class)
    public Map<String, String> handleInvalidCredentialsException(InvalidCredentialsException exp) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("success", "false");
        errorMap.put("message", exp.getMessage());
        return errorMap;
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(InvalidRefreshTokenException.class)
    public Map<String, String> handleInvalidRefreshTokenException(InvalidRefreshTokenException exp) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("success", "false");
        errorMap.put("message", exp.getMessage());
        return errorMap;
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(ServerSideException.class)
    public Map<String, String> handleServerSideException(ServerSideException exp) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("success", "false");
        errorMap.put("message", exp.getMessage());
        return errorMap;
    }
}
