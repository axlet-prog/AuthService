package com.example.AuthService.dto;

import lombok.Data;

@Data
public class LogoutRequestDto {
    private String refreshToken;
}
