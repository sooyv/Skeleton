package com.skeleton.common.auth.login.dto;

import lombok.Builder;
import lombok.Getter;

import java.util.Date;

@Getter @Builder
public class LoginResponse {
        private String accessToken;
        private long accessExpiresIn;
        private String userId;
        private String username;
        private String roles;
        private Date passwordExpiredAt;
}
