package com.skeleton.common.exception;


import com.skeleton.common.constraint.RspResultCodeEnum;
import com.skeleton.common.constraint.log.AuditLog;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.internal.util.Objects;

@Getter
@Slf4j
public class CommonException extends RuntimeException {
    private final RspResultCodeEnum code;
    private final AuditLog auditLog;
    private final Object detail;
    private final boolean isLog;

    public CommonException(RspResultCodeEnum code, AuditLog auditLog, Object detail, boolean isLog) {
        super(Objects.firstNonNull(code, RspResultCodeEnum.Undefined).getDesc());
        this.code = code;
        this.auditLog = auditLog;
        this.detail = detail;
        this.isLog = isLog;
    }

    public CommonException(RspResultCodeEnum code, AuditLog auditLog, boolean isLog) {
        super(Objects.firstNonNull(code, RspResultCodeEnum.Undefined).getDesc());
        this.code = code;
        this.auditLog = auditLog;
        this.detail = null;
        this.isLog = isLog;
    }

}
