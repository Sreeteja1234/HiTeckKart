package com.phegondev.Phegon.Eccormerce.security;

import com.phegondev.Phegon.Eccormerce.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Component
@Slf4j
public class JwtUtils {

    // 6 months
    private static final long EXPIRATION_TIME =
            1000L * 60 * 60 * 24 * 30 * 6;

    @Value("${jwt.secret}")
    private String jwtSecret;

    // 🔑 create signing key (HS256 needs 256-bit key)
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    // ================== TOKEN GENERATION ==================

    public String generateToken(User user) {
        return generateToken(user.getEmail());
    }

    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)                 // ✅ correct method
                .setIssuedAt(new Date())
                .setExpiration(new Date(
                        System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // ================== TOKEN VALIDATION ==================

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return username.equals(userDetails.getUsername())
                && !isTokenExpired(token);
    }

    // ================== CLAIM EXTRACTION ==================

    public String getUsernameFromToken(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration)
                .before(new Date());
    }

    private <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = Jwts.parserBuilder()          // ✅ MUST be parserBuilder
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        return resolver.apply(claims);
    }
}
