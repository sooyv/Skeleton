package com.skeleton.common.auth.login;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.skeleton.api.users.repository.UserRepository;
import com.skeleton.common.auth.AuthPasswordEncoder;
import com.skeleton.common.auth.CustomGrantedAuthority;
import com.skeleton.common.auth.login.dto.LoginRequest;
import com.skeleton.common.auth.login.dto.LoginResponse;
import com.skeleton.common.auth.login.dto.TokenDto;
import com.skeleton.common.auth.login.repository.LoginTokenRepository;
import com.skeleton.common.constraint.RspResultCodeEnum;
import com.skeleton.common.constraint.log.AuditLog;
import com.skeleton.common.entity.AuthRoleEnum;
import com.skeleton.common.entity.LoginTokenEntity;
import com.skeleton.common.entity.RoleEntity;
import com.skeleton.common.entity.UserEntity;
import com.skeleton.common.exception.CommonException;
import com.skeleton.common.token.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.el.parser.Token;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.naming.spi.ResolveResult;
import java.util.*;
import java.util.stream.Collectors;

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
        System.out.println("verify jwt 확인: ");

        // token substring
        String jwtToken = extractToken(jwt);

        // 토큰 미존재
        if (jwtToken == null || jwtToken.isBlank()) {
            throw new CommonException(RspResultCodeEnum.UnAuthorized, AuditLog.VerifyToken,  "토큰이 존재하지 않습니다.", false);
        }

        // subject(userId) validate
        String userId = jwtUtil.getSubject(jwtToken);
        if (userId == null && userId.isBlank()) {
            throw new CommonException(RspResultCodeEnum.UnAuthorized, AuditLog.VerifyToken,  "토큰에 userId(subject) 미존재", false);
        }

        // get userToken Entity from jwt token
        LoginTokenEntity tokenEntity = loginTokenRepository.findTokenByUserId(userId)
                .orElseThrow(() -> new CommonException(RspResultCodeEnum.UnAuthorized, AuditLog.VerifyToken,  "토큰에 userId(subject) 미존재", false));

        Optional<UserEntity> userEntity = Optional.ofNullable(userRepository.findByUserId(userId)
                .orElseThrow(() -> new CommonException(RspResultCodeEnum.UnAuthorized, AuditLog.VerifyToken, "유저 미존재", false)));
        UserEntity user = userEntity.get();  // Optional에서 UserEntity 추출


        String salt = userEntity.get().getSalt();
        JWTVerifier jwtVerifier = jwtUtil.jwtVerifier(salt);

        List<String> authorityGroupIds = Collections.singletonList(userEntity.get().getAuthorityGroupId());
        List<RoleEntity> roleEntities = roleRepository.findAllById(authorityGroupIds);
        Collection<CustomGrantedAuthority> authorities = roleEntities.stream()
                .map(role -> new CustomGrantedAuthority(role.getRoleName()))
                .collect(Collectors.toList());

        try {
            // 정상 토큰일 경우 pass
            jwtVerifier.verify(jwtToken);
        } catch (TokenExpiredException e) {
            //토큰 만료 시 재발급
            return reissueToken(userId, tokenEntity, salt, jwtToken);
        } catch (JWTVerificationException e) {
            throw new CommonException(RspResultCodeEnum.UnAuthorized, AuditLog.VerifyToken,"액세스 토큰 검증 실패", false);
        }

        return new LoginToken(user, authorities);
    }

    private LoginToken reissueToken(String userId, LoginTokenEntity tokenEntity, String salt, String jwtToken) {
        System.out.println("reissuToken 재발급 로직: ");
        String getDbRefreshToken = tokenEntity.getRefreshToken();
        if (getDbRefreshToken == null || getDbRefreshToken.isBlank()) {
            throw new CommonException(RspResultCodeEnum.UnAuthorized, AuditLog.VerifyToken, "리프레시 토큰 미존재", false);
        }

        JWTVerifier jwtVerifier = jwtUtil.jwtVerifier(salt);
        DecodedJWT decodedRefresh = jwtVerifier.verify(getDbRefreshToken);
        // refresh 의 sub 일치 확인
        if (!userId.equals(decodedRefresh.getSubject())) {
            throw new CommonException(RspResultCodeEnum.UnAuthorized, AuditLog.VerifyToken, "리프레시 토큰 subject 불일치", false);
        }

        // 새로운 accessToken, refreshToken 생성
        Map<String, Object> extParams = Map.of("user_id", tokenEntity.getUserId());
        Claim roles = jwtUtil.getClaim(jwtToken, "role");
        List<String> role = roles.asList(String.class);
        String newAccessToken = jwtUtil.generateJWT(userId, salt, extParams, role);
        String newRefreshToken = jwtUtil.generateRefreshToken(userId, salt);
        TokenDto tokenDto = new TokenDto();
        tokenDto.setAccessToken(newAccessToken);
        tokenDto.setRefreshToken(newRefreshToken);

        // 저장
        return saveOrUpdateToken(userId, tokenDto);
    }

    public LoginToken saveOrUpdateToken(String userId, TokenDto tokenDto) {
        Optional<LoginTokenEntity> optionalLoginToken = loginTokenRepository.findTokenByUserId(userId);
        if (optionalLoginToken.isPresent()) {
            LoginTokenEntity loginTokenEntity = optionalLoginToken.get();
            loginTokenEntity.updateTokens(tokenDto);
            loginTokenEntity = loginTokenRepository.save(loginTokenEntity);

            UserEntity userEntity = userRepository.findByUserId(userId)
                    .orElseThrow(() -> new CommonException(RspResultCodeEnum.UnAuthorized, AuditLog.VerifyToken, "유저 정보 찾을 수 없음.", false));

            List<String> authorityGroupIds = Collections.singletonList(userEntity.getAuthorityGroupId());  // 예를 들어 여러 권한 그룹 ID를 리스트로 가지고 있다고 가정
            List<RoleEntity> roleEntities = roleRepository.findAllById(authorityGroupIds);
            Collection<CustomGrantedAuthority> authorities = roleEntities.stream()
                    .map(role -> new CustomGrantedAuthority(role.getRoleName()))
                    .collect(Collectors.toList());

            LoginToken loginToken = new LoginToken(userEntity, authorities);
            loginToken.setJwt(loginTokenEntity.getAccessToken());
            loginToken.setLoginTime(userEntity.getLastLoginTime());

            return loginToken;
        }
        return null;
    }

    public String extractToken(String bearerToken) {
        System.out.println("bearerToken :" + bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        } else {
            // 다음 필터로 넘어감
            return null;
        }
    }

}