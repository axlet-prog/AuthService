package com.example.AuthService.services;

import com.example.AuthService.dto.*;
import com.example.AuthService.entity.RefreshToken;
import com.example.AuthService.entity.Role;
import com.example.AuthService.entity.User;
import com.example.AuthService.repository.RefreshTokenRepository;
import com.example.AuthService.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.apache.tomcat.util.descriptor.web.ContextHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
@AllArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(10);


    public AuthenticationResponseDto register(RegisterRequestDto registerRequestDto) {
        if (userRepository.existsByEmail(registerRequestDto.email()) || userRepository.existsByUsername(registerRequestDto.username())) {
            throw new RuntimeException();
        }
        User newUser = User.builder()
                .email(registerRequestDto.email())
                .username(registerRequestDto.username())
                .password_hash(bCryptPasswordEncoder.encode(registerRequestDto.password()))
                .role(Role.ROLE_CLIENT)
                .build();

        newUser = userRepository.save(newUser);

        String accessToken = jwtService.generateAccessToken(newUser);
        RefreshToken refreshToken = generateNewRefreshToken(newUser);
        return new AuthenticationResponseDto(
                accessToken,
                refreshToken.getTokenBody().toString()
        );
    }

    public AuthenticationResponseDto login(LoginRequestDto loginRequestDto) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequestDto.username(), loginRequestDto.password()));
        User user = userRepository.findByUsername(loginRequestDto.username()).orElseThrow(RuntimeException::new);
        String accessToken = jwtService.generateAccessToken(user);
        RefreshToken refreshToken = generateNewRefreshToken(user);
        return new AuthenticationResponseDto(
                accessToken,
                refreshToken.getTokenBody().toString()
        );
    }

    public AuthenticationResponseDto refresh(RefreshRequestDto refreshRequestDto) {
        UUID refreshTokenBody = UUID.fromString(refreshRequestDto.refreshToken());
        var refreshedToken = updateRefreshToken(refreshTokenBody);
        var accessToken = jwtService.generateAccessToken(refreshedToken.getOwner());
        return new AuthenticationResponseDto(
                accessToken,
                refreshedToken.getTokenBody().toString()
        );
    }

    public void logout(LogoutRequestDto logoutRequestDto) {
        UUID refreshTokenBody = UUID.fromString(logoutRequestDto.refreshToken());

        RefreshToken refreshToken = refreshTokenRepository.findByTokenBody(refreshTokenBody).orElseThrow(RuntimeException::new);
        refreshTokenRepository.delete(refreshToken);
        SecurityContextHolder.clearContext();
    }

    private RefreshToken generateNewRefreshToken(User user) {
        UUID tokenBody = UUID.randomUUID();
        var refreshToken =  RefreshToken.builder()
                .tokenBody(tokenBody)
                .owner(user)
                .expiryTime(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 20)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    private RefreshToken updateRefreshToken(UUID refreshTokenBody) {
        var oldToken = refreshTokenRepository.findByTokenBody(refreshTokenBody).orElseThrow(
                () -> new RuntimeException("Token not found")
        );

        var refreshedToken = generateNewRefreshToken(oldToken.getOwner());
        refreshTokenRepository.delete(oldToken);

        return refreshTokenRepository.save(refreshedToken);
    }
}
