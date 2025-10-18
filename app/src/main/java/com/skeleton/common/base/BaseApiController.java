package com.skeleton.common.base;


import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.skeleton.common.auth.login.LoginToken;
import com.skeleton.common.constraint.RspResultCodeEnum;
import com.skeleton.common.constraint.log.AuditLog;
import com.skeleton.common.exception.CommonException;
import com.skeleton.common.exception.ValidateException;
import com.skeleton.common.response.ResponseDto;
import com.skeleton.common.util.CommonUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RequestMapping("/api")
@Slf4j
public class BaseApiController {
    protected String getLoginedId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (isLoginUser()) return auth.getName();
        return "system";
    }

    protected boolean isLoginUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && (auth.getPrincipal() instanceof LoginToken);
    }

    protected String objToJson(Object o) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

            return mapper.writeValueAsString(o);

        } catch (Exception e) {
            log.error("json error: " + e);
            return "";
        }
    }

    public HashMap<String, Object> actor() {
        HashMap<String, Object> req = new HashMap<>();
        req.put("actor", getLoginedId());
        return req;
    }

    public ResponseEntity<?> rspInquirySuccess(AuditLog auditLog, String msg, Object data) {
        //성공일 경우 누가 어떤 행위를 했는지만 기록하는 경우
        log.debug("Response, Log:{}, Msg:{}, Data:{}", auditLog, msg, data);
        return ResponseEntity.ok().body(new ResponseDto(RspResultCodeEnum.Success, msg, null, data));
    }

    public ResponseEntity<?> rspSuccess(String msg, Object data) {
        return rspSuccess(null, msg, data, false);
    }

    public ResponseEntity<?> rspSuccess(AuditLog auditLog, Object data, boolean isLog) {
        return rspSuccess(auditLog, auditLog.getDesc(), data, isLog);
    }

    public ResponseEntity<?> rspSuccess(AuditLog auditLog, String msg, Object data, boolean isLog) {
        //exec
        log.debug("Response, Log:{}, Msg:{}, Data:{}", auditLog, msg, data);
        return ResponseEntity.ok().body(new ResponseDto(RspResultCodeEnum.Success, msg, null, data));
    }

    public ResponseEntity<?> rspError(AuditLog auditLog, RspResultCodeEnum result_code, String msg, Object detail, boolean isLog) {
        log.error("Error Response Log:{}, Msg:{}, Detail:{}", auditLog, msg, detail);
        ResponseDto errRsp = new ResponseDto(result_code, msg, detail, actor());
        return ResponseEntity.status(result_code.getStatus()).body(errRsp);
    }

    public ResponseEntity<?> rspError(AuditLog auditLog, RspResultCodeEnum result_code, Object detail, boolean isLog) {
        log.error("Error Response Log:{}, Detail:{}", auditLog, detail);
        ResponseDto errRsp = new ResponseDto(result_code, null, detail, null);
        return ResponseEntity.status(result_code.getStatus()).body(errRsp);
    }

    @ExceptionHandler(CommonException.class)
    protected ResponseEntity<?> commonPortalExHandler(CommonException e) {
        return rspError(e.getAuditLog(), e.getCode(), null, e.isLog());
    }

    @ExceptionHandler({BadCredentialsException.class, AuthenticationException.class
            , AccessDeniedException.class, IllegalAccessException.class})
    protected ResponseEntity<?> authExHandler() {
        return rspError(AuditLog.OPR_LOGIN_USER, RspResultCodeEnum.LoginFailed, null, true);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> validateExHandler(MethodArgumentNotValidException e) {
        return rspError(AuditLog.OPR_ISSUE,
                RspResultCodeEnum.InvalidParameter, null, true);
    }

    @ExceptionHandler(ValidateException.class)
    public ResponseEntity<?> validateExHandler(ValidateException e) {
        Map<String, String> errors = e.getErrors().stream().collect(Collectors.toMap(
                fieldError -> CommonUtils.convertToSnakeCase(fieldError.getField()),
                fieldError -> StringUtils.defaultIfEmpty(fieldError.getDefaultMessage(), "")));
        return rspError(e.getAuditLog(), RspResultCodeEnum.InvalidParameter, errors, true);
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<?> ioExHandler() {
        return rspError(AuditLog.OPR_ISSUE,
                RspResultCodeEnum.InternalIOException, null, true);
    }

    @ExceptionHandler(RuntimeException.class)
    protected ResponseEntity<?> exHandler(Exception e, HttpServletRequest request) {
        log.error(request.getRequestURI(), e);
        return rspError(AuditLog.OPR_ISSUE
                , RspResultCodeEnum.Undefined, null, true);
    }

    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ExceptionHandler(Exception.class)
    public Map<String, String> handle(Exception e, HttpServletRequest request) {
        log.error(request.getRequestURI(), e);
        Map<String, String> errorAttributes = new HashMap<>();
        errorAttributes.put("code", "NOT_IMPLEMENTED");
        errorAttributes.put("message", "권한이 없습니다.");
        return errorAttributes;
    }
}