package com.skeleton.common.entity;

import com.skeleton.common.auth.login.dto.TokenDto;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;


@Document(collection = "token")
@Builder
@Getter
@Setter
public class LoginTokenEntity {
    private String userId;
    private String accessToken;
    private String refreshToken;
    private Instant tokenExpiredAt;

    public void updateTokens(TokenDto tokenDto) {
        this.accessToken = tokenDto.getAccessToken();
        this.refreshToken = tokenDto.getRefreshToken();
    }
}
