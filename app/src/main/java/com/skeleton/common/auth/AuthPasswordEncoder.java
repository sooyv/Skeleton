package com.skeleton.common.auth;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.util.Base64;

@Component("authPasswordEncoder")
@Slf4j
public class AuthPasswordEncoder implements PasswordEncoder {

	@Override
	public String encode(CharSequence rawPw) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			md.update(rawPw.toString().getBytes());
			String result = Base64.getEncoder().encodeToString(md.digest());
			return new String(result);
		} catch(Exception e) {
			log.error(e.getMessage());
		}
		return null;
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		if(StringUtils.isEmpty(encodedPassword) || StringUtils.isEmpty(rawPassword)) return false;
		String encode = encode(rawPassword);

		return encodedPassword.equals(encode);
	}
}
