package com.skeleton.common.auth.login;


import com.skeleton.api.users.repository.UserRepository;
import com.skeleton.common.auth.CustomGrantedAuthority;
import com.skeleton.common.auth.LoginToken;
import com.skeleton.common.constraint.RspResultCodeEnum;
import com.skeleton.common.constraint.log.AuditLog;
import com.skeleton.common.entity.AuthRoleEnum;
import com.skeleton.common.entity.RoleEntity;
import com.skeleton.common.entity.UserEntity;
import com.skeleton.common.exception.CommonException;
import com.skeleton.common.token.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;


@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService implements UserDetailsService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public LoginToken loadUserByUsername(String userId) {
        // TODO. 여기에 받아온 userId 로 UserDetail 생성 후 return
        UserEntity user = userRepository.findByUserId(userId)
                .orElseThrow(() -> new CommonException(RspResultCodeEnum.FailedReqOauth, AuditLog.VerifyToken, "userId 찾을수없음", false));

        List<String> authorityGroupIds = List.of(user.getAuthorityGroupId());
        List<RoleEntity> roleEntities = roleRepository.findAllById(authorityGroupIds); // enum 값 List로 사용해야함, 중요한 권한을 일반 String 값으로 들고있으면 안됨 (AuthRoleEnum)
        // List<AuthRoleEnum> userRoles = ... 이런식으로 갖고있어야함
        List<CustomGrantedAuthority> authorities = createAuthorities(userRoles.toArray(String[]::new));

        if (user.getPasswordExpiredAt().before(new Date())) {
            authorities.add(createAuthority(AuthRoleEnum.PASSWORD_EXPIRED.name()));
        }
        return new LoginToken(user, authorities);
    }

    private List<CustomGrantedAuthority> createAuthorities(String... roles) {
        List<CustomGrantedAuthority> authorityList = new ArrayList<>();
        for (String role : roles) {
            authorityList.add(createAuthority(role));
        }
        return authorityList;
    }

    private CustomGrantedAuthority createAuthority(String role) {
        CustomGrantedAuthority authority = new CustomGrantedAuthority();
        authority.setAuthority(role);
        return authority;
    }

}
