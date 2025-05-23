package com.api.codeflow.jwt;

import com.api.codeflow.model.UserDetails;
import com.api.codeflow.repository.RoleRepository;
import com.api.codeflow.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JwtTokenUtils {
    private UserRepository userRepository;
    private RoleRepository roleRepository;

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.accessToken.lifetime}")
    private Duration accessTokenLifetime;

    @Value("${jwt.refreshToken.lifetime}")
    private Duration refreshTokenLifetime;

    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        List<String> roles = userDetails.getAuthorities().stream().map(
                GrantedAuthority::getAuthority
        ).collect(Collectors.toList());

        claims.put("roles", roles);
        Date issuedAt = new Date();
        Date expiration = new Date(issuedAt.getTime() + accessTokenLifetime.toMillis());

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(issuedAt)
                .setExpiration(expiration)
                .setSubject(userDetails.getUsername())
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .compact();
    }

    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        List<String> roles = userDetails.getAuthorities().stream().map(
                GrantedAuthority::getAuthority
        ).collect(Collectors.toList());

        claims.put("roles", roles);
        Date issuedAt = new Date();
        Date expiration = new Date(issuedAt.getTime() + refreshTokenLifetime.toMillis());

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(issuedAt)
                .setExpiration(expiration)
                .setSubject(userDetails.getUsername())
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = getAllClaimsFromToken(token);
            Date expiration = claims.getExpiration();
            return expiration.after(new Date()); // не истек ли он
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public String getUsername(String token) {
        return getAllClaimsFromToken(token).getSubject();
    }

    public List<String> getRoles(String token) {
        return getAllClaimsFromToken(token).get("roles", List.class);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret)
                .parseClaimsJws(token).getBody();
    }
}
