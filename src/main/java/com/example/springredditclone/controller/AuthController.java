package com.example.springredditclone.controller;

import com.example.springredditclone.config.ApplicationConfig;
import com.example.springredditclone.dto.AuthenticationResponse;
import com.example.springredditclone.dto.LoginRequest;
import com.example.springredditclone.dto.RegisterRequest;
import com.example.springredditclone.exception.*;
import com.example.springredditclone.handler.ResponseHandler;
import com.example.springredditclone.service.AuthService;
import com.example.springredditclone.service.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Arrays;
import java.util.UUID;


@RestController
@CrossOrigin
@RequestMapping(path = "/api/auth")
@AllArgsConstructor
public class AuthController {
    private final ApplicationConfig appConfig;
    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;
    private final ResponseHandler responseHandler;

    @PostMapping(path = "/signup")
    public ResponseEntity<Object> signup(@Valid @RequestBody RegisterRequest registerRequest) throws EmailAlreadyExistException, UsernameAlreadyExistException {
        authService.signup(registerRequest);
        return responseHandler.responseBuilder(true, "Account created successfully", HttpStatus.CREATED);
    }

    @GetMapping(path = "/verifyAccount/{token}")
    public ResponseEntity<Object> verifyAccount(@PathVariable String token) throws InvalidTokenException, UserNotFoundException, EmailAlreadyVerifiedException {
        authService.verifyAccount(token);
        return responseHandler.responseBuilder(true, "Account activated successfully", HttpStatus.OK);
    }

    @PostMapping(path = "/login")
    public ResponseEntity<Object> login(@Valid @RequestBody LoginRequest loginRequest) throws UserNotFoundException {
        AuthenticationResponse authenticationResponse = authService.login(loginRequest);
        String refreshToken = authService.generateRefreshToken(loginRequest);

        Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setDomain(appConfig.getDomain());
        refreshTokenCookie.setPath("/api/auth");
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setMaxAge(refreshTokenService.getRefreshTokenExpirationInMillis());
        HttpServletResponse servletResponse = ((ServletRequestAttributes)RequestContextHolder.getRequestAttributes()).getResponse();
        servletResponse.addCookie(refreshTokenCookie);

        return responseHandler.responseBuilder(true, "Logged in successfully", HttpStatus.OK, authenticationResponse);
    }

    @GetMapping(path = "/refresh")
    public ResponseEntity<Object> accessToken(@CookieValue(name = "refresh_token", defaultValue = "") String refreshToken) throws InvalidRefreshTokenException {
        AuthenticationResponse authenticationResponse = authService.accessToken(refreshToken);
        return responseHandler.responseBuilder(true, "Access Token generated successfully", HttpStatus.OK, authenticationResponse);
    }

    @GetMapping(path = "/logout")
    public ResponseEntity<Object> logout(@CookieValue(name = "refresh_token", defaultValue = "") String refreshToken) throws InvalidRefreshTokenException {
        authService.logout(refreshToken);

        Cookie refreshTokenCookie = new Cookie("refresh_token", null);
        refreshTokenCookie.setMaxAge(0);

        HttpServletResponse servletResponse = ((ServletRequestAttributes)RequestContextHolder.getRequestAttributes()).getResponse();
        servletResponse.addCookie(refreshTokenCookie);

        return responseHandler.responseBuilder(true, "Logged out successfully", HttpStatus.OK);
    }
}
