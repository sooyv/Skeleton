package com.skeleton.common.auth.login.dto;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class TokenDto {
    private String AccessToken;
    private String RefreshToken;
}
