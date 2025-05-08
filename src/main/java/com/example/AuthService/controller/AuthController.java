package com.example.AuthService.controller;

import com.example.AuthService.dto.*;
import com.example.AuthService.services.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponseDto> register(RegisterRequestDto registerRequestDto) {
        return ResponseEntity.ok(authenticationService.register(registerRequestDto));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponseDto> login(LoginRequestDto loginRequestDto) {
        return ResponseEntity.ok(authenticationService.login(loginRequestDto));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponseDto> refresh(RefreshRequestDto refreshRequestDto) {
        return ResponseEntity.ok(authenticationService.refresh(refreshRequestDto));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(LogoutRequestDto logoutRequestDto) {
        authenticationService.logout(logoutRequestDto);
        return ResponseEntity.ok().build();
    }
}
