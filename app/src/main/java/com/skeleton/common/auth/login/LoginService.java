package com.skeleton.common.auth.login;


import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.skeleton.api.users.repository.UserRepository;
import com.skeleton.common.auth.AuthPasswordEncoder;
import com.skeleton.common.auth.CustomGrantedAuthority;
import com.skeleton.common.auth.LoginToken;
import com.skeleton.common.auth.login.dto.LoginRequest;
import com.skeleton.common.auth.login.dto.LoginResponse;
import com.skeleton.common.auth.login.dto.TokenDto;
import com.skeleton.common.auth.login.repository.LoginTokenRepository;
import com.skeleton.common.constraint.RspResultCodeEnum;
import com.skeleton.common.constraint.log.AuditLog;
import com.skeleton.common.entity.AuthRoleEnum;
import com.skeleton.common.entity.UserTokenEntity;
import com.skeleton.common.entity.RoleEntity;
import com.skeleton.common.entity.UserEntity;
import com.skeleton.common.exception.CommonException;
import com.skeleton.common.token.repository.RoleRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
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
        System.out.println("login service login!!!");
        // 회원 존재 확인
        UserEntity user = userRepository.findByUserId(loginRequest.getUserId());

        // 비밀번호 일치 확인
        if (!authpasswordEncoder.matches(loginRequest.getPassword() + user.getSalt(), user.getPassword())) {
            // 실패 시 loginFail 증가 후 저장
            user = user.toBuilder()
                    .loginFail(user.getLoginFail() + 1)
                    .build();
            userRepository.save(user);
        }

        // 로그인 성공 시
        user = user.toBuilder()
                .loginFail(0)
                .lastLoginTime(new Date())
                .build();
        userRepository.save(user);

        // 토큰 생성
        LoginToken loginToken = generateLoginToken(user.getUserId());
        String refreshToken = jwtUtil.generateRefreshToken(user.getUserId(), user.getSalt());

        // 토큰 저장
        UserTokenEntity token = UserTokenEntity.builder()
                .userId(user.getUserId())
                .accessToken(loginToken.getJwt())
                .refreshToken(refreshToken)
                .build();
        loginTokenRepository.save(token);

        LoginResponse loginResponse = LoginResponse.builder()
                .accessToken(loginToken.getJwt())
                .userId(user.getUserId())
                .username(user.getName())
                .roles(user.getAuthorityGroupId())
                .passwordExpiredAt(user.getPasswordExpiredAt())
                .build();

        return loginResponse;
    }


    public LoginToken verifyJwt(String jwt) {
        System.out.println("verfiyJwt");

        // token substring
        String jwtToken = extractToken(jwt);

        // subject(userId) validate
        String userId = jwtUtil.getSubject(jwtToken);

        // get userToken Entity from jwt token
        UserTokenEntity userToken = loginTokenRepository.findByAccessToken(jwtToken)
                .orElseThrow(() -> new CommonException(RspResultCodeEnum.InvalidJwt, AuditLog.VerifyToken,  "토큰에 userId(subject) 미존재", false));

        UserEntity userEntity = userRepository.findByUserId(userId);
        // 현재 로그인한 사용자의 Login Token 만들어서 가지고 있기
        LoginToken loginToken = authService.loadUserByUsername(userId);
        loginToken.setJwt(jwtToken);

        // accessToken, refreshToken 둘 다 만료
        Instant refreshExp = jwtUtil.getExpiresAt(userToken.getRefreshToken());
        if (jwtUtil.getExpiresAt(jwtToken).isBefore(Instant.now()) && refreshExp.isBefore(Instant.now())) {
            logout(jwt);
            throw new CommonException(RspResultCodeEnum.ExpiredJwt, AuditLog.VerifyToken, false);
        }

        // accessToken 만료, refreshToken 유효
        if (jwtUtil.getExpiresAt(jwtToken).isBefore(Instant.now()) && !refreshExp.isBefore(Instant.now())) {
            loginToken = generateLoginToken(userToken.getUserId());
            jwtToken = loginToken.getJwt();
            String refreshToken = jwtUtil.generateRefreshToken(userEntity.getId(), userEntity.getSalt());

            // userToken accessToken 값 update
            userToken.setAccessToken(jwtToken);
            userToken.setRefreshToken(refreshToken);
            userToken.setTokenExpiredAt(jwtUtil.getExpiresAt(jwtToken));
            saveToken(userToken);
        }

        try {
            // 정상 토큰일 경우 pass
            jwtUtil.jwtVerifier(userEntity.getSalt()).verify(jwtToken);
        } catch (TokenExpiredException e) { // 이거 통으로 없애
            //토큰 만료 시 재발급
            // return reissueToken(userId, tokenEntity, salt, jwtToken); // Todo. 이런식으로 사용하면 뭐가 만료되고 유효한지 어떻게 알아? 위에서 로직으로 처리하고 여기 는 없애
        } catch (CommonException e) {
            throw new CommonException(RspResultCodeEnum.InvalidJwt, AuditLog.VerifyToken,"액세스 토큰 검증 실패", false);
        }

        return loginToken;
    }

    private LoginToken generateLoginToken(String userId) {
        LoginToken loginToken;
        try {
            loginToken = authService.loadUserByUsername(userId);
            loginToken.setLoginTime(new Date());

            UserEntity user = loginToken.getUserEntity();

            HashMap<String, String> extParam = new HashMap<>();

            extParam.put("name", user.getName());

            String jwt = jwtUtil.generateJWT(user.getUserId(), user.getSalt(), extParam, loginToken.getAuthorities());
            loginToken.setJwt(jwt);

        } catch (Exception ex) {
            throw new CommonException(RspResultCodeEnum.InvalidJwt, AuditLog.VerifyToken, true);
        }
        return loginToken;
    }

    public void logout() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        String authHeader = request.getHeader("authorization");
        logout(authHeader);
    }

    public void logout(String authToken) {
        // token substring
        authToken = extractToken(authToken);

        try {
            String userId = jwtUtil.getSubject(authToken);
            //Expired JWT
            try {
                loginTokenRepository.deleteByUserId(userId);
            } catch (Exception e) {
                throw new CommonException(RspResultCodeEnum.FailedConnectDB, AuditLog.OPR_LOGOUT_USER, "FailedConnectDB 로그아웃 실패", false);
            }
        } catch (CommonException ex) {
            throw new CommonException(RspResultCodeEnum.InvalidJwt, AuditLog.VerifyToken, "userId(subject) 없음", false);
        }
    }

    private void saveToken(UserTokenEntity entity) {
        try {
            loginTokenRepository.deleteByUserId(entity.getUserId());
            loginTokenRepository.save(entity);
        } catch (Exception e) {
            throw new CommonException(RspResultCodeEnum.FailedConnectDB, AuditLog.OPR_DELETE_TOKEN, "토큰 삭제 오류", false);
        }
    }

    private LoginToken reissueToken(String userId, UserTokenEntity userTokenEntity, String salt, String jwtToken) {
        System.out.println("reissuToken 재발급 로직: ");
        String getDbRefreshToken = userTokenEntity.getRefreshToken();
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
        Map<String, Object> extParams = Map.of("user_id", userTokenEntity.getUserId());
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
        Optional<UserTokenEntity> optionalLoginToken = loginTokenRepository.findTokenByUserId(userId);
        if (optionalLoginToken.isPresent()) {
            UserTokenEntity loginUserTokenEntity = optionalLoginToken.get();
            loginUserTokenEntity.updateTokens(tokenDto);
            loginUserTokenEntity = loginTokenRepository.save(loginUserTokenEntity);

            UserEntity userEntity = userRepository.findByUserId(userId);
            RoleEntity roleEntity = roleRepository.findById(userEntity.getAuthorityGroupId())
                    .orElseThrow(() -> new CommonException(RspResultCodeEnum.UnAuthorized, AuditLog.VerifyToken, "토큰 재발급", false));
            List<AuthRoleEnum> roles = roleEntity.getRoles();

            Collection<CustomGrantedAuthority> authorities = roles.stream()
                    .map(authRoleEnum -> new CustomGrantedAuthority(authRoleEnum.getRole()))
                    .collect(Collectors.toList());

            LoginToken loginToken = new LoginToken(userEntity, authorities);
            loginToken.setJwt(loginUserTokenEntity.getAccessToken());
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
            throw new CommonException(RspResultCodeEnum.InvalidJwt, AuditLog.VerifyToken,  "토큰이 존재하지 않습니다.", false);
        }
    }

}