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

import java.util.*;


@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService implements UserDetailsService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public LoginToken loadUserByUsername(String userId) {
        // TODO. 여기에 받아온 userId 로 UserDetail 생성 후 return
        UserEntity user = userRepository.findByUserId(userId);
//                .orElseThrow(() -> new CommonException(RspResultCodeEnum.FailedReqOauth, AuditLog.VerifyToken, "userId 찾을수없음", false));
        RoleEntity roleEntity = roleRepository.findById(user.getAuthorityGroupId())
                .orElseThrow(() -> new CommonException(RspResultCodeEnum.UnAuthorized, AuditLog.OPR_ISSUE, "권한 확인 불가", false));
        List<AuthRoleEnum> roles = roleEntity.getRoles();
        List<CustomGrantedAuthority> authorities = createAuthorities(roles.toArray(String[]::new));

        if (user.getPasswordExpiredAt().before(new Date())) {
            authorities.add(createAuthority(AuthRoleEnum.PASSWORD_EXPIRED.name()));
        } else {
            authorities.add(createAuthority(AuthRoleEnum.ACTIVE.name()));
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
        CustomGrantedAuthority authority = new CustomGrantedAuthority(role);
        authority.setAuthority(role);
        return authority;
    }

}
