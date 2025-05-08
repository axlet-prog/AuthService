package com.example.AuthService.services;

import com.example.AuthService.dto.AuthenticationResponseDto;
import com.example.AuthService.entity.User;
import com.example.AuthService.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class JwtService {

    private final UserRepository userRepository;

    JwtService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    @Value(value = "${secure.jwt.secret}")
    private String secret;

    public User verify(String token) {
        if (!isToken(token)) {
            throw new RuntimeException();
        }
        Claims claims = getClaims(token);
        String username = claims.getSubject();
        var user = userRepository.findByUsername(username).orElseThrow(
                () -> new RuntimeException("User not found")
        );
        return user;
    }


    private boolean isToken(String token) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    private Claims getClaims(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    public String generateAccessToken(User user) {
        Map<String, Object> extraClaims = new HashMap<>();

        extraClaims.put("id", user.getId());
        extraClaims.put("role", user.getRole());
        extraClaims.put("email", user.getEmail());

        return Jwts.builder()
                .setSubject(user.getUsername())
                .setClaims(extraClaims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 2))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

}
