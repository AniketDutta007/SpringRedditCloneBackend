package com.example.springredditclone.service;

import com.example.springredditclone.config.ApplicationConfig;
import com.example.springredditclone.dto.AuthenticationResponse;
import com.example.springredditclone.dto.LoginRequest;
import com.example.springredditclone.dto.RegisterRequest;
import com.example.springredditclone.exception.*;
import com.example.springredditclone.model.Name;
import com.example.springredditclone.model.RefreshToken;
import com.example.springredditclone.model.User;
import com.example.springredditclone.model.VerificationToken;
import com.example.springredditclone.repository.UserRepository;
import com.example.springredditclone.repository.VerificationTokenRepository;
import com.example.springredditclone.security.JWTProvider;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
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
import java.util.Optional;
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
    public User getCurrentUser() {
        Jwt principal = (Jwt) SecurityContextHolder.
                getContext().getAuthentication().getPrincipal();
        return userRepository.findByUsername(principal.getSubject())
                .orElseThrow(() -> new UsernameNotFoundException("User name not found - " + principal.getSubject()));
    }

    @Transactional
    public void signup(RegisterRequest registerRequest) throws UsernameAlreadyExistException, EmailAlreadyExistException {

        Optional<User> tuser = userRepository.findByUsername(registerRequest.getUsername());
        if (tuser.isPresent()) {
            throw new UsernameAlreadyExistException();
        }
        tuser = userRepository.findByEmail(registerRequest.getEmail());
        if (tuser.isPresent()) {
            throw new EmailAlreadyExistException();
        }

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

    public void verifyAccount(String token) throws InvalidTokenException, UserNotFoundException, EmailAlreadyVerifiedException {
        VerificationToken verficationToken = verificationTokenRepository.findByToken(token).orElseThrow(InvalidTokenException::new);
        fetchUserAndEnable(verficationToken);
    }

    @Transactional
    public void fetchUserAndEnable (VerificationToken verificationToken) throws UserNotFoundException, EmailAlreadyVerifiedException {
        Long userId = verificationToken.getUser().getId();
        User user = userRepository.findById(userId).orElseThrow(UserNotFoundException::new);
        if (user.isEnabled()) {
            throw new EmailAlreadyVerifiedException();
        }
        user.setEnabled(true);
        userRepository.save(user);
    }

    public AuthenticationResponse login(LoginRequest loginRequest) throws UserNotFoundException {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(),
                loginRequest.getPassword()
        );
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtProvider.generateToken(authentication);
        return AuthenticationResponse.builder()
                .accessToken(token)
                .expiresAt(Instant.now().plusMillis(jwtProvider.getJwtExpirationInMillis()))
                .username(loginRequest.getUsername())
                .build();
    }

    public String generateRefreshToken(LoginRequest loginRequest) throws UserNotFoundException {
        User user = userRepository.findByUsername(loginRequest.getUsername()).orElseThrow(UserNotFoundException::new);
        return refreshTokenService.generateRefreshToken(user).getToken().toString();
    }

    public AuthenticationResponse accessToken(String rtoken) throws InvalidRefreshTokenException {
        RefreshToken refreshToken = refreshTokenService.validateRefreshToken(rtoken);
        User user = refreshToken.getUser();
        String token = jwtProvider.generateTokenWithUsername(user.getUsername());
        return AuthenticationResponse.builder()
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
