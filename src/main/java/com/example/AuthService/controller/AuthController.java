package com.example.AuthService.controller;

import com.example.AuthService.dto.*;
import com.example.AuthService.entity.Role;
import com.example.AuthService.services.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

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
    public ResponseEntity<Void> verifyToken(@RequestHeader("Authorization") String token, @RequestParam(value = "role", defaultValue = "client") Set<String> roles) {
        boolean authorized = roles.stream().anyMatch((role) -> {
            try {
                Role userRole;
                switch (role.trim().toLowerCase()) {
                    case "admin" -> userRole = Role.ROLE_ADMIN;
                    case "client" -> userRole = Role.ROLE_CLIENT;
                    case "courier" -> userRole = Role.ROLE_COURIER;
                    default -> throw new IllegalStateException("Unexpected value: " + role);
                }
                String jwtToken = token.substring(7);
                return authenticationService.authorizeRequest(jwtToken, userRole);
            } catch (Exception e) {
                return false;
            }
        });
        if (authorized) {
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

    }

    @PostMapping("/parse_id")
    public ResponseEntity<Long> parseIdFromToken(@RequestHeader("Authorization") String token) {
        String jwtToken = token.substring(7);
        return ResponseEntity.ok(authenticationService.parseTokenForUserId(jwtToken));
    }

    @PostMapping("/parse_role")
    public ResponseEntity<String> parseRoleFromToken(@RequestHeader("Authorization") String token) {
        String jwtToken = token.substring(7);
        return ResponseEntity.ok(authenticationService.parseTokenForUserRole(jwtToken));
    }

    @PostMapping("/parse_role/{id}")
    public ResponseEntity<String> parseRoleFromId(@PathVariable("id") long userId) {
        return ResponseEntity.ok(authenticationService.getUserRole(userId));
    }

    @PostMapping("/change_role")
    public ResponseEntity<Void> changeRoleFromToken(@RequestBody ChangeRoleRequest request) {
        authenticationService.changeRole(request);
        return ResponseEntity.ok().build();
    }
}
