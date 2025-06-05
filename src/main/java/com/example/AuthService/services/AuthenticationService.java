package com.example.AuthService.services;

import com.example.AuthService.dto.*;
import com.example.AuthService.entity.RefreshToken;
import com.example.AuthService.entity.Role;
import com.example.AuthService.entity.UserEntity;
import com.example.AuthService.repository.RefreshTokenRepository;
import com.example.AuthService.repository.UserRepository;
import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@AllArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder bCryptPasswordEncoder;

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

        System.out.println("Registered user: " + newUserEntity);
        System.out.println("Password: " + bCryptPasswordEncoder.encode(newUserEntity.getPassword()));
        String accessToken = jwtService.generateAccessToken(newUserEntity);
        RefreshToken refreshToken = generateNewRefreshToken(newUserEntity);
        return new AuthenticationResponseDto(
                accessToken,
                refreshToken.getTokenBody().toString()
        );
    }

    public AuthenticationResponseDto login(LoginRequestDto loginRequestDto) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginRequestDto.getUsername(),
                loginRequestDto.getPassword()
        ));

        UserEntity userEntity = userRepository.findByUsername(loginRequestDto.getUsername()).orElseThrow(RuntimeException::new);
        String accessToken = jwtService.generateAccessToken(userEntity);
        RefreshToken refreshToken = generateNewRefreshToken(userEntity);
        return new AuthenticationResponseDto(
                accessToken,
                refreshToken.getTokenBody().toString()
        );
    }

    public AuthenticationResponseDto refresh(RefreshRequestDto refreshRequestDto) {
        UUID refreshTokenBody = UUID.fromString(refreshRequestDto.getRefreshToken());
        var refreshedToken = updateRefreshToken(refreshTokenBody);
        var accessToken = jwtService.generateAccessToken(refreshedToken.getOwner());
        return new AuthenticationResponseDto(
                accessToken,
                refreshedToken.getTokenBody().toString()
        );
    }

    public void logout(LogoutRequestDto logoutRequestDto) {
        UUID refreshTokenBody = UUID.fromString(logoutRequestDto.getRefreshToken());

        RefreshToken refreshToken = refreshTokenRepository.findByTokenBody(refreshTokenBody).orElseThrow(RuntimeException::new);
        refreshTokenRepository.delete(refreshToken);
        SecurityContextHolder.clearContext();
    }

    public boolean authorizeRequest(String token, Role role) {
        Claims claims = jwtService.getClaims(token);
        long idFromToken = claims.get("id", Long.class);
        String username = claims.getSubject();

        UserEntity userEntity = userRepository.findById(idFromToken).orElseThrow(RuntimeException::new);
        if (!userEntity.getUsername().equals(username)) {
            throw new RuntimeException();
        }

        return userEntity.getRole().equals(role);
    }

    public Long parseTokenForUserId(String token) {
        return jwtService.getIdFromToken(token);
    }

    public String parseTokenForUserRole(String token) {
        return jwtService.getRoleFromToken(token);
    }

    public String getUserRole(long userId) {
        UserEntity userEntity = userRepository.findById(userId).orElseThrow(
                () -> new RuntimeException("user with id " + userId + " not found")
        );
        return userEntity.getRole().toString();
    }

    public void changeRole(ChangeRoleRequest request) {
        long targetUserId = request.getUserId();
        UserEntity userEntity = userRepository.findById(targetUserId).orElseThrow(
                () -> new RuntimeException("user with id " + targetUserId + " not found")
        );
        userEntity.setRole(request.getNewRole());
        userRepository.save(userEntity);
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
