package com.example.AuthService.dto;

public record AuthenticationResponseDto(
        String accessToken,
        String refreshToken
) {
}
