package com.example.AuthService.controller;

import com.example.AuthService.dto.*;
import com.example.AuthService.entity.Role;
import com.example.AuthService.services.AuthenticationService;
import com.example.AuthService.services.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponseDto> register(@RequestBody RegisterRequestDto registerRequestDto) {
        return ResponseEntity.ok(authenticationService.register(registerRequestDto));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponseDto> login(@RequestBody LoginRequestDto loginRequestDto) {
        return ResponseEntity.ok(authenticationService.login(loginRequestDto));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponseDto> refresh(@RequestBody RefreshRequestDto refreshRequestDto) {
        return ResponseEntity.ok(authenticationService.refresh(refreshRequestDto));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequestDto logoutRequestDto) {
        authenticationService.logout(logoutRequestDto);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/verify")
    public ResponseEntity<Void> verifyToken(@RequestHeader("Authorization") String token, @RequestParam(value = "role", defaultValue = "client") String role) {
        try {
            Role userRole;
            switch (role.trim().toLowerCase()) {
                case "admin" -> userRole = Role.ROLE_ADMIN;
                case "client" -> userRole = Role.ROLE_CLIENT;
                case "courier" -> userRole = Role.ROLE_COURIER;
                default -> throw new IllegalStateException("Unexpected value: " + role);
            }
            String jwtToken = token.substring(7);
            if (authenticationService.authorizeRequest(jwtToken, userRole)) {
                return ResponseEntity.ok().build();
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
