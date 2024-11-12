package ua.dragunovskiy.webfluxsecurity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import ua.dragunovskiy.webfluxsecurity.entity.UserEntity;
import ua.dragunovskiy.webfluxsecurity.exception.AuthException;
import ua.dragunovskiy.webfluxsecurity.repository.UserRepository;
import ua.dragunovskiy.webfluxsecurity.service.UserService;

import javax.crypto.SecretKey;
import java.util.*;

@Component
@RequiredArgsConstructor
public class SecurityService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Integer expirationInSeconds;

    @Value("${jwt.issuer}")
    private String issuer;

    private TokenDetails generateToken(UserEntity user) {
        Map<String, Object> claims = new HashMap<>(){{
            put("role", user.getRole());
            put("username", user.getUsername());
        }};
        return generateToken(claims, user.getId().toString());
    }

    private TokenDetails generateToken(Map<String, Object> claims, String subject) {
        Long expirationTimeInMillis = expirationInSeconds * 1000L;
        Date expirationDate = new Date(new Date().getTime() + expirationTimeInMillis);
        return generateToken(expirationDate, claims, subject);
    }

    // case with deprecated methods:
//    private TokenDetails generateToken(Date expirationDate, Map<String, Object> claims, String subject) {
//        Date createdDate = new Date();
//        String token = Jwts.builder()
//                .setClaims(claims)
//                .setIssuer(issuer)
//                .setSubject(subject)
//                .setIssuedAt(createdDate)
//                .setId(UUID.randomUUID().toString())
//                .setExpiration(expirationDate)
//                .signWith(SignatureAlgorithm.HS256, Base64.getEncoder().encodeToString(secret.getBytes()))
//                .compact();

        private TokenDetails generateToken(Date expirationDate, Map<String, Object> claims, String subject) {
            SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
            Date createdDate = new Date();
            String token = Jwts.builder()
                    .claims(claims)
                    .issuer(issuer)
                    .subject(subject)
                    .issuedAt(createdDate)
                    .id(UUID.randomUUID().toString())
                    .expiration(expirationDate)
                    .signWith(key)
                    .compact();


        return TokenDetails.builder()
                .token(token)
                .issuedAt(createdDate)
                .expiresAt(expirationDate)
                .build();
    }
    public Mono<TokenDetails> authenticate(String name, String password) {
       return userService.getUserByUserName(name)
                .flatMap(user -> {
                    if (!user.isEnabled()) {
                        return Mono.error(new AuthException("Account disabled", "DRAHUNOVSKIY_USER_ACCOUNT_DISABLED"));
                    }

                    if (!passwordEncoder.matches(password, user.getPassword())) {
                        return Mono.error(new AuthException("Invalid password", "DRAHUNOVSKIY_INVALID_PASSWORD"));
                    }
                    return Mono.just(generateToken(user).toBuilder()
                                    .userId(user.getId())
                            .build());
                })
                .switchIfEmpty(Mono.error(new AuthException("Invalid username", "DRAHUNOVSKIY_INVALID_USERNAME")));
    }
}
