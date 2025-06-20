package com.hotel.api.hotelauthapi.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${jwt.secret.access}")
    private String accessSecret;

    @Value("${jwt.secret.refresh}")
    private String refreshSecret;

    @Value("${jwt.expiration.access}")
    private long accessExpiration;

    @Value("${jwt.expiration.refresh}")
    private long refreshExpiration;

    public String extractUsername(String token, boolean isAccessToken) {
        return extractClaim(token, Claims::getSubject, isAccessToken);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver, boolean isAccessToken) {
        final Claims claims = extractAllClaims(token, isAccessToken);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token, boolean isAccessToken) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey(isAccessToken))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSigningKey(boolean isAccessToken) {
        byte[] keyBytes = Decoders.BASE64.decode(isAccessToken ? accessSecret : refreshSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails, accessExpiration, true);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails, refreshExpiration, false);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails, long expirationTime, boolean isAccessToken) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(getSigningKey(isAccessToken), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails, boolean isAccessToken) {
        final String username = extractUsername(token, isAccessToken);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token, isAccessToken);
    }

    private boolean isTokenExpired(String token, boolean isAccessToken) {
        return extractExpiration(token, isAccessToken).before(new Date());
    }

    private Date extractExpiration(String token, boolean isAccessToken) {
        return extractClaim(token, Claims::getExpiration, isAccessToken);
    }
}
