package com.skeleton.common.constraint.log;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.skeleton.common.constraint.AuditCode;
import lombok.AllArgsConstructor;


@AllArgsConstructor
@JsonFormat(shape = JsonFormat.Shape.OBJECT)
@AuditCode
public enum AuditLog implements LogInfo {
    //Operation
    OPR_COMMON("000", "operation", "공용 코드 로그 기록x"),

    //인증
    OPR_LOGIN_USER("101", "operation", "사용자 로그인"),
    OPR_LOGOUT_USER("", "operation", "사용자 로그아웃"),
    OPR_PASSWORD_EXPIRED("", "operation", "패스워드 만료"),

    //등록
    OPR_ENROLL_USER("201", "operation", "사용자 등록"),

    //수정
    OPR_MODIFY_USER("301", "operation", "사용자 정보 수정"),

    //삭제
    OPR_DELETE_USER("401", "operation", "사용자 삭제"),
    OPR_DELETE_TOKEN("402", "operation", "토큰 삭제"),

    // auth
    IssueToken("012", "auth", "Access Token 발급"),
    VerifyToken("013", "auth", "Access Token 검증"),
    RemoveToken("014", "auth", "Refresh token 폐기"),
    CreateUser("015", "auth", "인증 사용자 추가"),
    ChangeUser("016", "auth", "인증 사용자 정보 변경"),
    CreateUrlRole("017", "auth", "URL role 생성"),
    ChangeUrlRole("018", "auth", "URL role 변경"),

    //오류 또는 이슈
    OPR_ISSUE("801", "operation", "이슈"),
    OPR_WRONG_APPROACH("811", "operation", "잘못된 접근"),
    ;

    private final String code;
    private final String type;
    private final String desc;

    @Override
    @JsonIgnore
    public String getCode() {
        return this.code;
    }

    @Override
    @JsonIgnore
    public String getType() {
        return this.type;
    }

    @Override
    @JsonProperty("display")
    public String getDesc() {
        return this.desc;
    }

    @JsonProperty("value")
    public String getValue() {
        return this.type + ":" + this.code;
    }

}
