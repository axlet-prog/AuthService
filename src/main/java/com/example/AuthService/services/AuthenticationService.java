package com.example.AuthService.services;

import com.example.AuthService.dto.*;
import com.example.AuthService.entity.RefreshToken;
import com.example.AuthService.entity.Role;
import com.example.AuthService.entity.UserEntity;
import com.example.AuthService.repository.RefreshTokenRepository;
import com.example.AuthService.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

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
        if (userRepository.existsByEmail(registerRequestDto.getEmail()) || userRepository.existsByUsername(registerRequestDto.getUsername())) {
            throw new RuntimeException();
        }
        UserEntity newUserEntity = UserEntity.builder()
                .email(registerRequestDto.getEmail())
                .username(registerRequestDto.getUsername())
                .password_hash(bCryptPasswordEncoder.encode(registerRequestDto.getPassword()))
                .role(Role.ROLE_CLIENT)
                .build();

        newUserEntity = userRepository.save(newUserEntity);

        String accessToken = jwtService.generateAccessToken(newUserEntity);
        RefreshToken refreshToken = generateNewRefreshToken(newUserEntity);
        return new AuthenticationResponseDto(
                accessToken,
                refreshToken.getTokenBody().toString()
        );
    }

    public AuthenticationResponseDto login(LoginRequestDto loginRequestDto) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequestDto.username(), loginRequestDto.password()));
        UserEntity userEntity = userRepository.findByUsername(loginRequestDto.username()).orElseThrow(RuntimeException::new);
        String accessToken = jwtService.generateAccessToken(userEntity);
        RefreshToken refreshToken = generateNewRefreshToken(userEntity);
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

    private RefreshToken generateNewRefreshToken(UserEntity userEntity) {
        UUID tokenBody = UUID.randomUUID();
        var refreshToken = RefreshToken.builder()
                .tokenBody(tokenBody)
                .owner(userEntity)
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
