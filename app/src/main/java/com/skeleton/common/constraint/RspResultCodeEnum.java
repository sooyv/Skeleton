package com.skeleton.common.constraint;


import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum RspResultCodeEnum {

    /*
     1. 코드 정리시 ErrorSchema Web Front 로 전달
     2. 응답 메시지 분할 및 정리
     3. 응답 코드값 구조화
            HTTP STATUS: 200:OK,  401:UNAUTHORIZED, 400:BAD_REQUEST, 503:SERVICE_UNAVAILABLE, 500:INTERNAL_SERVER_ERROR

            401: 인증 관련
            400: 파라미터, 정규식 검증 오류
            503: 연동 모듈 요청 및 처리 오류
            500: 서버 오류
     */

    //Success
    Success("00", HttpStatus.OK, "success"),

    //Login, Auth X UNAUTHORIZED(401, Series.CLIENT_ERROR, "Unauthorized"),
    LoginFailed("01", HttpStatus.UNAUTHORIZED, "로그인 인증 실패"),
    PasswordExpired("02", HttpStatus.UNAUTHORIZED, "패스워드 만료"),
    UnAuthorized("03", HttpStatus.UNAUTHORIZED, "권한이 없습니다."),
    DuplicateUser("", HttpStatus.UNAUTHORIZED, "중복된 사용자 정보."),
    InvalidParameter("", HttpStatus.UNAUTHORIZED, "유효하지 않은 파라미터."),

    // 5X SERVICE_UNAVAILABLE(503, Series.SERVER_ERROR, "Service Unavailable"),
    UnProcessable("100", HttpStatus.SERVICE_UNAVAILABLE, "Unprocessable"),
    FailedReqOauth("", HttpStatus.SERVICE_UNAVAILABLE, "oauth 요청 실패"),

    //Server 6X INTERNAL_SERVER_ERROR(500, Series.SERVER_ERROR, "Internal Server Error"),
    InternalError("200", HttpStatus.INTERNAL_SERVER_ERROR, "server error"),
    InternalIOException("", HttpStatus.INTERNAL_SERVER_ERROR, "No contents, I/O Exception"),
    FailedConnectDB("", HttpStatus.INTERNAL_SERVER_ERROR, "Database 오류"),

    //Undefined 99
    Undefined("99", HttpStatus.INTERNAL_SERVER_ERROR, "정의되지 않은 예외"),
    ;
    @JsonProperty("value")
    private final String code;
    @JsonIgnore
    private final HttpStatus status;
    @JsonProperty("display")
    private final String desc;

    RspResultCodeEnum(String code, HttpStatus status, String desc) {
        this.code = code;
        this.status = status;
        this.desc = desc;
    }

}
