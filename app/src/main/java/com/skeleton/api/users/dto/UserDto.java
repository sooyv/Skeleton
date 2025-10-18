package com.skeleton.api.users.dto;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Getter;

import java.util.Date;

@Getter
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class UserDto {
    private String userId;
    private String name;
    private String password;
    private String salt;
    private String email;
    private String mobileNum;
    private Date lastLoginTime;
    private Date passwordExpiredAt;
    private long loginFail;
    private String authorityGroupId;
}
