package com.example.AuthService.config;

import com.example.AuthService.entity.Role;
import com.example.AuthService.entity.UserEntity;
import com.example.AuthService.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class StartAppRunner implements CommandLineRunner {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @Value("${admin.username}")
    private String adminUsername;

    @Value("${admin.password}")
    private String adminPassword;

    @Value("${admin.email}")
    private String adminEmail;

    public StartAppRunner(PasswordEncoder passwordEncoder, UserRepository userRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }

    @Override
    public void run(String... args) throws Exception {
        if (userRepository.findByUsername(adminUsername).isEmpty()) {
            userRepository.save(
                    UserEntity.builder()
                            .email(adminEmail)
                            .username(adminUsername)
                            .password_hash(passwordEncoder.encode(adminPassword))
                            .role(Role.ROLE_ADMIN)
                            .build()
            );
        }
    }
}