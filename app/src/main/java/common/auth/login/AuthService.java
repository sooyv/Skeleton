package common.auth.login;


import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;


@Service
@Slf4j
public class AuthService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String userId) {
        // TODO. 여기에 받아온 userId 로 UserDetail 생성 후 return
        return null;
    }
}
