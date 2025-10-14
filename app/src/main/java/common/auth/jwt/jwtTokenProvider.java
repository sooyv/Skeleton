package common.auth.jwt;

import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Date;

@Slf4j
@Component
@PropertySource("classpath:app.properties")
@RequiredArgsConstructor
public class jwtTokenProvider {

    private final String SECRET_KEY;
    private final long EXPIRE_TIME;

    public String generateToken(Authentication authentication) {
        return generateToken(authentication.getName(), authentication.getAuthorities());
    }

    private String generateToken(String username, Collection<? extends GrantedAuthority> authorities) {
        return Jwts.builder()
                .setSubject(username)
                .claim("", authorities.stream().findFirst().get().toString())
                .setExpiration(getExprieDate())
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
            .compact();
    }

    public String resolveToken(HttpServletRequest request) {
        return request.getHeader("Authorization");
    }

    public Authentication getauthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);

        if (claims.get("auth") == null) {

        }
        return null;
    }

    public boolean validateToken(String accessToken) {
        try {
            Jwts.parser().setSigningKey(SECRET_KEY).build().parseClaimsJws(accessToken);
            return true;

        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
        } catch (UnsupportedJwtException e) {
            log.info("UnsupportedJwtException", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
        } catch (Exception e) {
            log.info("JWT Signature is invalid.", e);
        }
        return false;
    }

    private Date getExprieDate() {
        Date now = new Date();
        return new Date(now.getTime() + EXPIRE_TIME);
    }

    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parser().setSigningKey(SECRET_KEY).build().parseSignedClaims(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }


}
