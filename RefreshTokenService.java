
package com.hotel.api.hotelauthapi.service;

import com.hotel.api.hotelauthapi.model.RefreshToken;
import com.hotel.api.hotelauthapi.model.User;
import com.hotel.api.hotelauthapi.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService; // To get refresh token expiration property

    @Value("${jwt.expiration.refresh}")
    private long refreshExpiration;

    public RefreshToken createRefreshToken(User user) {
        // Delete any existing refresh token for this user
        refreshTokenRepository.deleteByUser(user);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString()) // Or use JWT for the refresh token
                .expiryDate(Instant.now().plusMillis(refreshExpiration))
                .build();
        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    @Transactional
    public void deleteRefreshTokenByUser(User user) {
        refreshTokenRepository.deleteByUser(user);
    }
}