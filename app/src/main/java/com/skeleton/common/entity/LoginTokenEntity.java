package com.skeleton.common.entity;

import lombok.Builder;
import lombok.Getter;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;


@Document(collection = "token")
@Builder
@Getter
public class LoginTokenEntity {
    private String userId;
    private String accessToken;
    private String refreshToken;
}
