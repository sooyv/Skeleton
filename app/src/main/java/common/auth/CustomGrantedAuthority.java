package common.auth;

import org.springframework.security.core.GrantedAuthority;

public class CustomGrantedAuthority implements GrantedAuthority {

	private static final String _ROLE_PREFIX = "ROLE_";

	private String auth;

	@Override
	public String getAuthority() {
		return (auth.toUpperCase().startsWith(_ROLE_PREFIX))? auth : _ROLE_PREFIX + auth;
	}
	public void setAuthority(String auth) {
		this.auth = auth;
	}
	public String toString() {
		return this.auth;
	}
}
