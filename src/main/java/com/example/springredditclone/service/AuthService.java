package com.example.springredditclone.service;

import com.example.springredditclone.config.ApplicationConfig;
import com.example.springredditclone.dto.AuthenticationResponse;
import com.example.springredditclone.dto.LoginRequest;
import com.example.springredditclone.dto.RegisterRequest;
import com.example.springredditclone.exception.InvalidRefreshTokenException;
import com.example.springredditclone.exception.InvalidTokenException;
import com.example.springredditclone.exception.UserNotFoundException;
import com.example.springredditclone.model.Name;
import com.example.springredditclone.model.RefreshToken;
import com.example.springredditclone.model.User;
import com.example.springredditclone.model.VerificationToken;
import com.example.springredditclone.repository.UserRepository;
import com.example.springredditclone.repository.VerificationTokenRepository;
import com.example.springredditclone.security.JWTProvider;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import sendinblue.ApiException;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final SendMailService mailService;
    private final AuthenticationManager authenticationManager;
    private final JWTProvider jwtProvider;
    private final AsyncTaskExecutor asyncTaskExecutor;
    private final RefreshTokenService refreshTokenService;
    private final ApplicationConfig appConfig;

    @Transactional
    public User getCurrentUser() throws UserNotFoundException {
        Jwt principal = (Jwt) SecurityContextHolder.
                getContext().getAuthentication().getPrincipal();
        return userRepository.findByUsername(principal.getSubject())
                .orElseThrow(() -> new UsernameNotFoundException("User name not found - " + principal.getSubject()));
    }

    @Transactional
    public void signup (RegisterRequest registerRequest) {
        Name name = new Name();
        name.setFirstname(registerRequest.getName().getFirstname());
        name.setMiddlename(registerRequest.getName().getMiddlename());
        name.setLastname(registerRequest.getName().getLastname());

        User user = new User();
        user.setName(name);
        user.setUsername(registerRequest.getUsername());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setCreated(Instant.now());
        user.setEnabled(false);

        userRepository.save(user);

        String token = generateVerificationToken(user);

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("FIRSTNAME", user.getName().getFirstname());
        parameters.put("VERIFICATION_LINK", appConfig.getUrl()+"/api/auth/verifyAccount/"+token);


        asyncTaskExecutor.execute(() -> {
            try {
                mailService.sendMail(user.getEmail(), 1L, parameters);
            } catch (ApiException e) {
                System.err.println(e.getMessage());
            }
        });
    }

    @Transactional
    public String generateVerificationToken(User user) {
        String token = UUID.randomUUID().toString();

        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setToken(token);
        verificationToken.setUser(user);

        verificationTokenRepository.save(verificationToken);
        return token;
    }

    public void verifyAccount(String token) throws InvalidTokenException, UserNotFoundException {
        VerificationToken verficationToken = verificationTokenRepository.findByToken(token).orElseThrow(InvalidTokenException::new);
        fetchUserAndEnable(verficationToken);
    }

    @Transactional
    public void fetchUserAndEnable (VerificationToken verificationToken) throws UserNotFoundException {
        Long userId = verificationToken.getUser().getId();
        User user = userRepository.findById(userId).orElseThrow(UserNotFoundException::new);
        user.setEnabled(true);
        userRepository.save(user);
    }

    public AuthenticationResponse login(LoginRequest loginRequest) throws UserNotFoundException {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(),
                loginRequest.getPassword()
        ));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        User user = userRepository.findByUsername(loginRequest.getUsername()).orElseThrow(UserNotFoundException::new);
        String token = jwtProvider.generateToken(authentication);
        return AuthenticationResponse.builder()
                .accessToken(token)
                .refreshToken(refreshTokenService.generateRefreshToken(user).getToken())
                .expiresAt(Instant.now().plusMillis(jwtProvider.getJwtExpirationInMillis()))
                .username(loginRequest.getUsername())
                .build();
    }

    public AuthenticationResponse accessToken(String rtoken) throws InvalidRefreshTokenException {
        RefreshToken refreshToken = refreshTokenService.validateRefreshToken(rtoken);
        User user = refreshToken.getUser();
        String token = jwtProvider.generateTokenWithUsername(user.getUsername());
        return AuthenticationResponse.builder()
                .refreshToken(rtoken)
                .accessToken(token)
                .username(user.getUsername())
                .expiresAt(Instant.now().plusMillis(jwtProvider.getJwtExpirationInMillis()))
                .build();
    }

    public void logout(String refreshToken) throws InvalidRefreshTokenException {
        refreshTokenService.validateRefreshToken(refreshToken);
        refreshTokenService.deleteRefreshToken(refreshToken);
    }
}
