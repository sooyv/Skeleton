package com.skeleton.common.auth.login;


import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.skeleton.api.users.repository.UserRepository;
import com.skeleton.api.users.service.UserServiceImpl;
import com.skeleton.common.auth.AuthPasswordEncoder;
import com.skeleton.common.auth.CustomGrantedAuthority;
import com.skeleton.common.auth.login.dto.LoginRequest;
import com.skeleton.common.auth.login.dto.LoginResponse;
import com.skeleton.common.auth.login.repository.LoginTokenRepository;
import com.skeleton.common.constraint.RspResultCodeEnum;
import com.skeleton.common.constraint.log.AuditLog;
import com.skeleton.common.entity.AuthRoleEnum;
import com.skeleton.common.entity.LoginTokenEntity;
import com.skeleton.common.entity.RoleEntity;
import com.skeleton.common.entity.UserEntity;
import com.skeleton.common.exception.CommonException;
import com.skeleton.common.token.repository.RoleRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class LoginService {
    private final JwtUtil jwtUtil;
    private final AuthService authService;
    private final UserRepository userRepository;
    private final LoginTokenRepository loginTokenRepository;
    private final RoleRepository roleRepository;
    private final AuthPasswordEncoder authpasswordEncoder;


    @Transactional
    public LoginResponse login(LoginRequest loginRequest) {
        System.out.println("login service");
        // 회원 존재 확인
        UserEntity user = userRepository.findByUserId(loginRequest.getUserId())
                .orElseThrow(() -> new CommonException(
                        RspResultCodeEnum.FailedReqOauth, AuditLog.OPR_LOGIN_USER, "userId 찾을 수 없음", false)
                );

        // 비밀번호 일치 확인
        if (!authpasswordEncoder.matches(loginRequest.getPassword() + user.getSalt(), user.getPassword())) {
            // 실패 시 loginFail 증가 후 저장
            user = user.toBuilder()
                    .loginFail(user.getLoginFail() + 1)
                    .build();
            userRepository.save(user);
        }

        // 권한 확인 (ROLE)
        Optional<RoleEntity> roleEntity = roleRepository.findById(user.getAuthorityGroupId());
        String role = AuthRoleEnum.valueOf(roleEntity.get().getRoleName()).getRole();
        System.out.println("확인1" + AuthRoleEnum.valueOf(roleEntity.get().getRoleName()));
        System.out.println("확인2" + role);

        // 로그인 성공 시
        user = user.toBuilder()
                .loginFail(0)
                .lastLoginTime(new Date())
                .build();
        userRepository.save(user);

        // 토큰 발급 및 저장
        Map<String, Object> extParams = Map.of("user_id", user.getUserId());
        List<String> roles = List.of(user.getAuthorityGroupId());
        String accessToken = jwtUtil.generateJWT(
                user.getUserId(),
                user.getSalt(),
                extParams,
                roles
        );

        String refreshToken = jwtUtil.generateRefreshToken(user.getUserId(), user.getSalt());

        LoginTokenEntity token = LoginTokenEntity.builder()
                .userId(user.getUserId())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
        loginTokenRepository.save(token);

        LoginResponse loginResponse = LoginResponse.builder()
                .accessToken(accessToken)
//                .accessExpiresIn(accessToken)
                .userId(user.getUserId())
                .username(user.getName())
                .roles(role)
                .passwordExpiredAt(user.getPasswordExpiredAt())
                .build();

        return loginResponse;
    }


    public LoginToken verifyJwt(String jwt) {
        // token substring
        String jwtToken = extractToken(jwt);

        // subject(userId) validate
        Claim claim = jwtUtil.getClaim(jwtToken, "sub");

        // get userToken Entity from jwt token

        // DB 토큰 조회
//        Optional<LoginTokenEntity> tokenEntity = loginTokenRepository.findTokenByUserId(userEntity.getUserId());
//        System.out.println("loginService 토큰 확인: " + tokenEntity.get());

        // TODO. 재발급
        // accessToken, refreshToken 둘 다 만료 시
        // accessToken 만료, refreshToken 유효

        return null;
    }

    private String extractToken(String bearerToken) {
        System.out.println("bearerToken :" + bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        } else {
            // 다음 필터로 넘어감
            return null;
        }
    }

}