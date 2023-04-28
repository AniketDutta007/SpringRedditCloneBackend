package com.example.springredditclone.controller;

import com.example.springredditclone.dto.AuthenticationResponse;
import com.example.springredditclone.dto.LoginRequest;
import com.example.springredditclone.dto.RegisterRequest;
import com.example.springredditclone.exception.*;
import com.example.springredditclone.handler.ResponseHandler;
import com.example.springredditclone.service.AuthService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin
@RequestMapping(path = "/api/auth")
@AllArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final ResponseHandler responseHandler;

    @PostMapping(path = "/signup")
    public ResponseEntity<Object> signup(@Valid @RequestBody RegisterRequest registerRequest) throws EmailAlreadyExistException, UsernameAlreadyExistException {
        authService.signup(registerRequest);
        return responseHandler.responseBuilder(true, "Account created successfully", HttpStatus.CREATED);
    }

    @GetMapping(path = "/verifyAccount/{token}")
    public ResponseEntity<Object> verifyAccount(@PathVariable String token) throws InvalidTokenException, UserNotFoundException {
        authService.verifyAccount(token);
        return responseHandler.responseBuilder(true, "Account activated successfully", HttpStatus.OK);
    }

    @PostMapping(path = "/login")
    public ResponseEntity<Object> login(@Valid @RequestBody LoginRequest loginRequest) throws UserNotFoundException {
        AuthenticationResponse authenticationResponse = authService.login(loginRequest);
        return responseHandler.responseBuilder(true, "Logged in successfully", HttpStatus.OK, authenticationResponse);
    }

    @GetMapping(path = "/access/token")
    public ResponseEntity<Object> accessToken(@RequestParam("refresh_token") String refreshToken) throws InvalidRefreshTokenException {
        AuthenticationResponse authenticationResponse = authService.accessToken(refreshToken);
        return responseHandler.responseBuilder(true, "Access Token generated successfully", HttpStatus.OK, authenticationResponse);
    }

    @GetMapping(path = "/logout")
    public ResponseEntity<Object> logout(@RequestParam("refresh_token") String refreshToken) throws InvalidRefreshTokenException {
        authService.logout(refreshToken);
        return responseHandler.responseBuilder(true, "Logged out successfully", HttpStatus.OK);
    }
}
