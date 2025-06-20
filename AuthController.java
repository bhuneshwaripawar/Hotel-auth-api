package com.hotel.api.hotelauthapi.controller;

import com.hotel.api.hotelauthapi.dto.AuthRequest;
import com.hotel.api.hotelauthapi.dto.AuthResponse;
import com.hotel.api.hotelauthapi.dto.RefreshTokenRequest;
import com.hotel.api.hotelauthapi.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody AuthRequest request) {
        authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully. Please login.");
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No user authenticated for logout.");
        }
        authService.logout(userDetails.getUsername());
        return ResponseEntity.ok("Logged out successfully.");
    }

    @GetMapping("/test-protected")
    public ResponseEntity<String> testProtectedEndpoint(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok("Hello, " + userDetails.getUsername() + "! You have accessed a protected endpoint.");
    }
}
