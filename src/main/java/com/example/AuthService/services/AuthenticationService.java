package com.example.AuthService.services;

import com.example.AuthService.dto.*;
import com.example.AuthService.entity.RefreshToken;
import com.example.AuthService.entity.Role;
import com.example.AuthService.entity.UserEntity;
import com.example.AuthService.repository.RefreshTokenRepository;
import com.example.AuthService.repository.UserRepository;
import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Log4j2
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder bCryptPasswordEncoder;

    public AuthenticationResponseDto register(RegisterRequestDto registerRequestDto) {
        log.info("Attempting to register new user with username: {}", registerRequestDto.getUsername());
        if (userRepository.existsByEmail(registerRequestDto.getEmail()) || userRepository.existsByUsername(registerRequestDto.getUsername())) {
            log.warn("Registration failed: username '{}' or email '{}' already exists.", registerRequestDto.getUsername(), registerRequestDto.getEmail());
            throw new RuntimeException("Username or email already exists");
        }
        UserEntity newUserEntity = UserEntity.builder()
            .email(registerRequestDto.getEmail())
            .username(registerRequestDto.getUsername())
            .password_hash(bCryptPasswordEncoder.encode(registerRequestDto.getPassword()))
            .role(Role.ROLE_CLIENT)
            .build();

        userRepository.save(newUserEntity);
        log.info("User '{}' saved successfully with ID: {}", newUserEntity.getUsername(), newUserEntity.getId());

        String accessToken = jwtService.generateAccessToken(newUserEntity);
        RefreshToken refreshToken = generateNewRefreshToken(newUserEntity);

        log.info("User '{}' registered and tokens generated successfully.", newUserEntity.getUsername());
        return new AuthenticationResponseDto(
            accessToken,
            refreshToken.getTokenBody().toString()
        );
    }

    public AuthenticationResponseDto login(LoginRequestDto loginRequestDto) {
        log.info("Attempting to login user: {}", loginRequestDto.getUsername());
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginRequestDto.getUsername(),
                loginRequestDto.getPassword()
            ));
        } catch (AuthenticationException e) {
            log.warn("Login failed for user '{}': Invalid credentials", loginRequestDto.getUsername());
            throw new AuthenticationException("Invalid username or password") {};
        }

        UserEntity userEntity = userRepository.findByUsername(loginRequestDto.getUsername())
            .orElseThrow(() -> new RuntimeException("User not found after successful authentication"));
        log.info("User '{}' authenticated successfully.", userEntity.getUsername());

        String accessToken = jwtService.generateAccessToken(userEntity);
        RefreshToken refreshToken = generateNewRefreshToken(userEntity);
        log.info("Generated new access and refresh tokens for user '{}'.", userEntity.getUsername());

        return new AuthenticationResponseDto(
            accessToken,
            refreshToken.getTokenBody().toString()
        );
    }

    public AuthenticationResponseDto refresh(RefreshRequestDto refreshRequestDto) {
        log.info("Attempting to refresh token.");
        UUID refreshTokenBody = UUID.fromString(refreshRequestDto.getRefreshToken());
        var refreshedToken = updateRefreshToken(refreshTokenBody);
        var accessToken = jwtService.generateAccessToken(refreshedToken.getOwner());
        log.info("Successfully refreshed token for user: {}", refreshedToken.getOwner().getUsername());
        return new AuthenticationResponseDto(
            accessToken,
            refreshedToken.getTokenBody().toString()
        );
    }

    public void logout(LogoutRequestDto logoutRequestDto) {
        UUID refreshTokenBody = UUID.fromString(logoutRequestDto.getRefreshToken());
        log.info("Attempting to logout with refresh token.");

        RefreshToken refreshToken = refreshTokenRepository.findByTokenBody(refreshTokenBody).orElseThrow(() -> {
            log.warn("Logout failed: Refresh token not found.");
            return new RuntimeException("Refresh token not found");
        });

        log.info("Deleting refresh token for user: {}", refreshToken.getOwner().getUsername());
        refreshTokenRepository.delete(refreshToken);
        SecurityContextHolder.clearContext();
        log.info("User {} logged out successfully.", refreshToken.getOwner().getUsername());
    }

    public boolean authorizeRequest(String token, Role role) {
        log.debug("Authorizing request for role: {}", role);
        try {
            Claims claims = jwtService.getClaims(token);
            long idFromToken = claims.get("id", Long.class);
            String username = claims.getSubject();

            UserEntity userEntity = userRepository.findById(idFromToken).orElseThrow(() -> {
                log.warn("Authorization failed: User with ID {} not found in database.", idFromToken);
                return new RuntimeException("User not found from token");
            });

            if (!userEntity.getUsername().equals(username)) {
                log.warn("Authorization failed: Token username '{}' does not match database username '{}'.", username, userEntity.getUsername());
                throw new RuntimeException("Token-username mismatch");
            }

            boolean isAuthorized = userEntity.getRole().equals(role);
            log.info("Authorization check for user '{}' for role '{}': {}", username, role, isAuthorized ? "Success" : "Failed");
            return isAuthorized;
        } catch (Exception e) {
            log.error("An error occurred during token authorization: {}", e.getMessage());
            return false;
        }
    }

    public Long parseTokenForUserId(String token) {
        log.debug("Parsing user ID from token.");
        Long userId = jwtService.getIdFromToken(token);
        log.debug("Successfully parsed user ID: {}", userId);
        return userId;
    }

    public String parseTokenForUserRole(String token) {
        log.debug("Parsing user role from token.");
        String role = jwtService.getRoleFromToken(token);
        log.debug("Successfully parsed user role: {}", role);
        return role;
    }

    public String getUserRole(long userId) {
        log.info("Fetching role for user ID: {}", userId);
        UserEntity userEntity = userRepository.findById(userId).orElseThrow(
            () -> {
                log.warn("Could not find user with ID: {}", userId);
                return new RuntimeException("user with id " + userId + " not found");
            }
        );
        log.info("Found role '{}' for user ID: {}", userEntity.getRole(), userId);
        return userEntity.getRole().toString();
    }

    public void changeRole(ChangeRoleRequest request) {
        long targetUserId = request.getUserId();
        log.info("Attempting to change role for user ID: {} to new role: {}", targetUserId, request.getNewRole());
        UserEntity userEntity = userRepository.findById(targetUserId).orElseThrow(
            () -> {
                log.warn("Change role failed: User with ID {} not found", targetUserId);
                return new RuntimeException("user with id " + targetUserId + " not found");
            }
        );
        userEntity.setRole(request.getNewRole());
        userRepository.save(userEntity);
        log.info("Successfully changed role for user ID: {} to {}", targetUserId, request.getNewRole());
    }

    private RefreshToken generateNewRefreshToken(UserEntity userEntity) {
        UUID tokenBody = UUID.randomUUID();
        long expiryTime = System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 20; // 20 days
        var refreshToken = RefreshToken.builder()
            .tokenBody(tokenBody)
            .owner(userEntity)
            .expiryTime(expiryTime)
            .build();

        RefreshToken savedToken = refreshTokenRepository.save(refreshToken);
        log.info("Generated new refresh token for user '{}'.", userEntity.getUsername());
        return savedToken;
    }

    private RefreshToken updateRefreshToken(UUID refreshTokenBody) {
        log.info("Updating refresh token.");
        var oldToken = refreshTokenRepository.findByTokenBody(refreshTokenBody).orElseThrow(
            () -> {
                log.warn("Refresh token update failed: Token not found.");
                return new RuntimeException("Token not found");
            }
        );
        UserEntity owner = oldToken.getOwner();
        log.info("Found existing refresh token for user: {}", owner.getUsername());

        refreshTokenRepository.delete(oldToken);
        log.info("Deleted old refresh token for user: {}", owner.getUsername());

        return generateNewRefreshToken(owner);
    }
}
