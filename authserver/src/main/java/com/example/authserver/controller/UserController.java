package com.example.authserver.controller;

import com.example.authserver.model.AuthRequest;
import com.example.authserver.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class UserController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostConstruct
    public void addDummyData() {
        save(new AuthRequest("rajesh@gmail.com", "hello123", List.of("ADMIN", "USER")));
    }

    @PostMapping("/signup")
    public String save(AuthRequest authRequest) {
        authRequest.setPassword(passwordEncoder.encode(authRequest.getPassword()));
        userRepository.save(authRequest);
        return "user saved successfully";
    }
}
