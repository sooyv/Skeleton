package common.auth.login;

import lombok.Getter;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.Key;


@Component
@Slf4j
@Getter
public class JwtUtil {
    public static final String AUTHORIZATION_HEADER = "";
    public static final String AUTHEORIZATION_KEY = "";
    public static final String BEARER_PREFIX = "bearer ";
    private final long TOKEN_TIME = 30*60*1000L; //30분

//    @Value
    private String SecretKey;
    private Key key;
//    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;


}
