package common.auth.login;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class LoginService {
    private final JwtUtil jwtUtil;

    // TODO. 여기에 로그인 로직 작성

    public LoginToken verifyJwt(String jwt) {
        // token substring
        String jwtToken = extractToken(jwt);

        // subject(userId) validate

        // get userToken Entity from jwt token

        // accessToken, refreshToken 둘 다 만료 시

        // accessToken 만료, refreshToken 유효

        return null;
    }

    private String extractToken(String bearerToken) {
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        } else {
            // Todo. exception 작성
            return null;
        }
    }
}