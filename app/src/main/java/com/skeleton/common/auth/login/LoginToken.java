package com.skeleton.common.auth.login;


import com.skeleton.common.auth.CustomGrantedAuthority;
import com.skeleton.common.entity.UserEntity;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.util.Collection;
import java.util.Date;

@Getter
@Setter
public class LoginToken implements UserDetails {

    @Serial
    private static final long serialVersionUID = -4980612368981092116L;

    private UserEntity userEntity;
    private String loginedIp;
    private String jwt;

    private Date loginTime;

    private Collection<CustomGrantedAuthority> authorities;

    public LoginToken(UserEntity userEntity) {
        this.userEntity = userEntity;
        this.loginTime = userEntity.getLastLoginTime();
    }

    public LoginToken(UserEntity userEntity, Collection<CustomGrantedAuthority> authorities) {
        this(userEntity);
        this.authorities = authorities;
    }

    @Override
    public Collection<CustomGrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    @Override
    public String getUsername() {
        return userEntity.getUserId();
    }

    public String getName() {
        return userEntity.getName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return userEntity.getPasswordExpiredAt().after(new Date());
    }

    @Override
    public boolean isEnabled() {
        return isAccountNonExpired() && isAccountNonLocked() && isCredentialsNonExpired();
    }

}
