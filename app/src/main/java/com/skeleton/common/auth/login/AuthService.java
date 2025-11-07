package com.skeleton.common.auth.login;


import com.skeleton.api.users.repository.UserRepository;
import com.skeleton.common.constraint.RspResultCodeEnum;
import com.skeleton.common.constraint.log.AuditLog;
import com.skeleton.common.entity.UserEntity;
import com.skeleton.common.exception.CommonException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;



@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String userId) {
        // TODO. 여기에 받아온 userId 로 UserDetail 생성 후 return
        UserEntity user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new CommonException(
                        RspResultCodeEnum.FailedReqOauth, AuditLog.VerifyToken, "userId 찾을수없음", false
                ));

        return new LoginToken(user);
    }
}
