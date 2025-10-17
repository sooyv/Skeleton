package common.response;


import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import common.constraint.RspResultCodeEnum;
import lombok.Getter;
import lombok.Setter;

import java.util.Objects;

@Getter
@Setter
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class ResponseDto {

    private String code;
    private String msg;
    private Object detail;
    private Object data;
    private String resultCode;


    public ResponseDto() {
    }

    public ResponseDto(RspResultCodeEnum result, String msg, Object detail, Object data) {
        this.code = result.getCode();
        if (msg == null) {
            this.msg = "";
        } else {
            this.msg = msg;
        }
        this.detail = Objects.requireNonNullElse(detail, "");
        this.data = Objects.requireNonNullElse(data, "");
    }
}
