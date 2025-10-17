package common.exception;

import common.constraint.RspResultCodeEnum;
import common.constraint.log.AuditLog;
import lombok.Getter;
import org.springframework.validation.FieldError;

import java.io.Serial;
import java.util.List;

@Getter
public class ValidateException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1919195365863666766L;

    List<FieldError> errors;
    String target;
    AuditLog auditLog;

    public ValidateException(List<FieldError> errors, AuditLog auditLog) {
        super(RspResultCodeEnum.InvalidParameter.getDesc());
        this.target = "";
        this.errors = errors;
        this.auditLog = auditLog;
    }

    public ValidateException(String target, List<FieldError> errors, AuditLog auditLog) {
        super(RspResultCodeEnum.InvalidParameter.getDesc());
        this.target = target;
        this.errors = errors;
        this.auditLog = auditLog;
    }

}
