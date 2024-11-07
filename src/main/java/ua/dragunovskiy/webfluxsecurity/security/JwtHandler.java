package ua.dragunovskiy.webfluxsecurity.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import reactor.core.publisher.Mono;
import ua.dragunovskiy.webfluxsecurity.exception.AuthException;
import ua.dragunovskiy.webfluxsecurity.exception.UnauthorizedException;

import java.util.Base64;
import java.util.Date;

public class JwtHandler {
    private final String secret;

    public JwtHandler(String secret) {
        this.secret = secret;
    }

    public Mono<VerificationResult> check(String accessToken) {
        return Mono.just(verify(accessToken))
                .onErrorResume(e -> Mono.error(new UnauthorizedException(e.getMessage())));
    }

    private VerificationResult verify(String token) {
        Claims claims = getClaimsFromToken(token);
        final Date expirationDate = claims.getExpiration();
        if (expirationDate.before(new Date())) {
            throw new RuntimeException("Token expired");
        }
        return new VerificationResult(claims, token);
    }

    // different way with build(). in lesson it was without build()
//    private Claims getClaimsFromToken(String token) {
//        return Jwts.parser()
//                .setSigningKey(Base64.getEncoder().encodeToString(secret.getBytes())
//                .parseClaimsJws(token)
//                .getBody();
//    }

    private Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(Base64.getEncoder().encodeToString(secret.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    public static class VerificationResult {
        public Claims claims;
        public String token;

        public VerificationResult(Claims claims, String token) {
            this.claims = claims;
            this.token = token;
        }
    }
}
