
package com.hotel.api.hotelauthapi.service;

import com.hotel.api.hotelauthapi.dto.AuthRequest;
import com.hotel.api.hotelauthapi.dto.AuthResponse;
import com.hotel.api.hotelauthapi.dto.RefreshTokenRequest;
import com.hotel.api.hotelauthapi.model.RefreshToken;
import com.hotel.api.hotelauthapi.model.Role;
import com.hotel.api.hotelauthapi.model.User;
import com.hotel.api.hotelauthapi.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;

    @Transactional
    public AuthResponse register(AuthRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already registered");
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER) // Default role
                .build();
        userRepository.save(user);

        // For registration, we don't return tokens directly. User should login after registration.
        // However, if you want to auto-login, uncomment below:
        /*
        String jwtToken = jwtService.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);
        return AuthResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken.getToken())
                .expiresIn(jwtService.getAccessExpiration()) // You might need a getter in JwtService
                .build();
        */
        return AuthResponse.builder().build(); // Or a simple success message DTO
    }

    public AuthResponse login(AuthRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String jwtAccessToken = jwtService.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user); // Creates new or updates existing

        return AuthResponse.builder()
                .accessToken(jwtAccessToken)
                .refreshToken(refreshToken.getToken())
                .expiresIn(Long.parseLong(jwtService.extractClaim(jwtAccessToken, claims -> claims.getExpiration().getTime() - claims.getIssuedAt().getTime(), true).toString())) // Calculate expiry
                .build();
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new RuntimeException("Refresh token not found!"));

        refreshTokenService.verifyExpiration(refreshToken);

        User user = refreshToken.getUser();
        String newAccessToken = jwtService.generateAccessToken(user);
        // Optionally, generate a new refresh token (refresh token rotation)
        // RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user);
        // If not rotating, keep the existing refresh token

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken.getToken()) // Or newRefreshToken.getToken() if rotating
                .expiresIn(Long.parseLong(jwtService.extractClaim(newAccessToken, claims -> claims.getExpiration().getTime() - claims.getIssuedAt().getTime(), true).toString()))
                .build();
    }

    @Transactional
    public void logout(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found for logout"));
        refreshTokenService.deleteRefreshTokenByUser(user);
    }
}