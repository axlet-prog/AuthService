package com.example.AuthService.dto;

import com.example.AuthService.entity.Role;
import lombok.Data;

@Data
public class ChangeRoleRequest {
    private long userId;
    private Role newRole;
}
