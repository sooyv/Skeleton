package common.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum AuthRoleEnum {
    // role
    USER("회원"),
    ADMIN("관리자"),

    // userStatus
    ACTIVE("활성화"),
    INACTIVE("비활성화"),
    PASSWORD_EXPIRED("패스워드 만료");


    private final String desc;

    public String getRole() {
        return "ROLE_" + name();
    }
}
