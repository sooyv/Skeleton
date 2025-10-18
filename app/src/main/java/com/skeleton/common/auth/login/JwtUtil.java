package com.skeleton.common.auth.login;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.skeleton.common.auth.CustomGrantedAuthority;
import com.skeleton.common.entity.AuthRoleEnum;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;


@Component
@Slf4j
@Getter
public class JwtUtil {
    public static final Duration SHORT_EXPIRE_DURATION = Duration.ofMinutes(10);
    public static final Duration jwtExpireAtDuration = Duration.ofMinutes(5);
    public static final Duration refreshExpireAtDuration = Duration.ofMinutes(10);
    private final String jwtIssuer = "system";


    String shortTimeJWT(String subject, String salt) {

        Algorithm alg = Algorithm.HMAC512(salt);
        Instant now = Instant.now();
        return JWT.create().withSubject(subject)
                .withIssuer(jwtIssuer)
                .withClaim("role", List.of(AuthRoleEnum.PASSWORD_EXPIRED.getRole()))
                .withIssuedAt(now)
                .withNotBefore(now)
                .withExpiresAt(now.plus(SHORT_EXPIRE_DURATION))
                .sign(alg);
    }

    String generateJWT(String subject, String salt, Map<String, ?> extParams, List<String> roles) {

        Algorithm alg = Algorithm.HMAC512(salt);
        Instant now = Instant.now();

        return JWT.create().withSubject(subject)
                .withIssuer(jwtIssuer)
                .withClaim("ext", extParams)
                .withClaim("role", roles)
                .withIssuedAt(now)
                .withNotBefore(now)
                .withExpiresAt(now.plus(jwtExpireAtDuration))
                .sign(alg);
    }

    String generateJWT(String subject, String salt, Map<String, ?> extParams, Collection<CustomGrantedAuthority> roles) {
        return generateJWT(subject, salt, extParams, roles.stream().map(CustomGrantedAuthority::getAuthority).toList());
    }

    public String generateRefreshToken(String subject, String salt) {

        Algorithm alg = Algorithm.HMAC512(salt);
        Instant now = Instant.now();

        return JWT.create().withSubject(subject)
                .withIssuedAt(now)
                .withExpiresAt(now.plus(refreshExpireAtDuration))
                .sign(alg);
    }

    String getSubject(String jwt) {
        String subject = JWT.decode(jwt).getSubject();
        if (subject == null) {
            // Todo. exception 작성
        }
        return subject;
    }

    Claim getClaim(String jwt, String claimKey) {
        Claim claim = JWT.decode(jwt).getClaim(claimKey);
        if (claim == null || claim.isNull()) {
            // Todo. exception 작성
        }
        return claim;
    }

    Instant getExpiresAt(String jwt) {
        Instant subject = JWT.decode(jwt).getExpiresAtAsInstant();
        if (subject == null) {
            // Todo. exception 작성
        }
        return subject;
    }

    JWTVerifier jwtVerifier(String salt) {
        Algorithm alg = Algorithm.HMAC512(salt);
        return JWT.require(alg)
                .withIssuer(jwtIssuer)
                .build();
    }
}
