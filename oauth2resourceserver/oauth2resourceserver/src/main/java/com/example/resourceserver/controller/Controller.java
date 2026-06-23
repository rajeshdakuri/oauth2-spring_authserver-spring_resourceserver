package com.example.resourceserver.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/secured/admin")
    public String admin() {
        return "hello from admin";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/secured/user")
    public String user() {
        return "hello from user";
    }

    @GetMapping("/secured")
    public String secured() {
        return "hello this is secured endpoint";
    }

    @GetMapping("/public")
    public String publicep() {
        return "this is public endpoint";
    }
}
