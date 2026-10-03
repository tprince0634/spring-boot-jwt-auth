package com.ampta.userauth.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;


@Component
public class JwtService {
    private final SecretKey secretKey;
    private final Long expirationMs;

    public JwtService(@Value("${jwt.secret}") String secretKey, @Value("${jwt.expirationMs}") Long expirationMs){
        this.secretKey = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    public String generateToken(String email, String role) {
        Date now = new Date(); // Gets the current date and time.
        return Jwts.builder() // Creates a JWT builder.
                .subject(email) // Stores the user's email as the JWT subject.
                .claim("role", role) // Stores the user's role as a custom claim.
                .issuedAt(now) // Stores the token creation time.
                .expiration(new Date(now.getTime() + expirationMs)) // Sets when the token will expire.
                .signWith(secretKey, Jwts.SIG.HS256) // Signs the JWT using the secret key and HS256.
                .compact(); // Converts the JWT builder into the final JWT string.
    }



    /*While extracting it, the JWT library parses/validates the token → this is where expiry/signature validation can happen,
    depending on how your JwtService is implemented.*/

    public String extractSubject(String token) {
        return Jwts.parser() // Creates a JWT parser.
                .verifyWith(secretKey) // Verifies the JWT using the secret key.
                .build() // Builds the JWT parser.
                .parseSignedClaims(token) // Parses and validates the signed JWT.
                .getPayload() // Gets the JWT payload.
                .getSubject(); // Gets the subject (email) from the JWT.
    }

}
