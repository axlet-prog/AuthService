package com.example.AuthService.dto;

public record RegisterRequestDto (
   String username,
   String password,
   String email
) {}
