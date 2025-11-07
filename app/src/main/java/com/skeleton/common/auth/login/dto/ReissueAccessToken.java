package com.skeleton.common.auth.login.dto;

import com.skeleton.common.auth.CustomGrantedAuthority;
import lombok.Getter;

import java.util.Collection;
import java.util.Map;

@Getter
public class ReissueAccessToken {
    String userId;
    String salt;
    Map<String, ?> extParams;
    Collection<CustomGrantedAuthority> roles;
    String oldToken;
}
