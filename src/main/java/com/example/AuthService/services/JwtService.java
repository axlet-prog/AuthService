package com.example.AuthService.services;

import com.example.AuthService.entity.UserEntity;
import com.example.AuthService.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private final UserRepository userRepository;
    @Value(value = "${secure.jwt.secret}")
    private String secret;

    JwtService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public UserEntity verify(String token) {
        if (!isToken(token)) {
            throw new RuntimeException();
        }
        Claims claims = getClaims(token);
        String username = claims.getSubject();
        return userRepository.findByUsername(username).orElseThrow(
                () -> new RuntimeException("User not found")
        );
    }

    private boolean isToken(String token) {
        try {
            Claims claims = Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token).getPayload();
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    public Claims getClaims(String token) {
        return Jwts.parser().verifyWith(getSigningKey()).build().parseSignedClaims(token).getPayload();
    }

    public Long getIdFromToken(String token) {
        return extractClaim(token, claims -> claims.get("id", Long.class));
    }

    public String getRoleFromToken(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = getClaims(token);
        return claimsResolver.apply(claims);
    }


    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(UserEntity userEntity) {
        Map<String, Object> extraClaims = new HashMap<>();

        extraClaims.put("id", userEntity.getId());
        extraClaims.put("role", userEntity.getRole());

        return Jwts.builder()
                .subject(userEntity.getUsername())
                .claims(extraClaims)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 2))
                .signWith(getSigningKey())
                .compact();
    }
}
