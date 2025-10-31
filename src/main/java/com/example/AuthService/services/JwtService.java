package com.example.AuthService.services;

import com.example.AuthService.entity.UserEntity;
import com.example.AuthService.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Log4j2
@Service
@RequiredArgsConstructor
public class JwtService {

    private final UserRepository userRepository;
    @Value(value = "${secure.jwt.secret}")
    private String secret;

    public UserEntity verify(String token) {
        log.info("Verifying token.");
        if (!isToken(token)) {
            log.error("Token verification failed: Invalid token format or signature.");
            throw new RuntimeException("Invalid token");
        }
        Claims claims = getClaims(token);
        String username = claims.getSubject();
        log.info("Token verified for user: {}", username);
        return userRepository.findByUsername(username).orElseThrow(
            () -> {
                log.warn("User '{}' from a valid token not found in the database.", username);
                return new RuntimeException("User not found");
            }
        );
    }

    private boolean isToken(String token) {
        try {
            Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token);
            log.debug("Token validation successful.");
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        } catch (Exception e) {
            log.error("An unexpected error occurred during token validation: {}", e.getMessage());
        }
        return false;
    }

    public Claims getClaims(String token) {
        log.debug("Extracting claims from token.");
        return Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token).getPayload();
    }

    public Long getIdFromToken(String token) {
        log.debug("Extracting user ID from token.");
        return extractClaim(token, claims -> claims.get("id", Long.class));
    }

    public String getRoleFromToken(String token) {
        log.debug("Extracting user role from token.");
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getClaims(token);
        return claimsResolver.apply(claims);
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(UserEntity userEntity) {
        log.info("Generating access token for user: {}", userEntity.getUsername());
        Map<String, Object> extraClaims = new HashMap<>();

        extraClaims.put("id", userEntity.getId());
        extraClaims.put("role", userEntity.getRole());

        String token = Jwts.builder()
            .subject(userEntity.getUsername())
            .claims(extraClaims)
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 2)) // 2 hours
            .signWith(getSigningKey())
            .compact();

        log.info("Access token generated successfully for user: {}", userEntity.getUsername());
        return token;
    }
}