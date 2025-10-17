package common.entity;

import lombok.Builder;
import lombok.Getter;
import org.springframework.data.annotation.*;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@Document(collection = "users")
@Builder
@Getter
public class UserEntity {
    @Id
    private String id;
    @CreatedBy
    private String createId;
    @CreatedDate
    private Date createAt;
    @LastModifiedBy
    private String updateId;
    @LastModifiedDate
    private Date updateAt;

    private String userId;
    private String name;
    private String password;
    private String salt;
    private String email;
    private String mobileNum;
    private Date lastLoginTime;
    private Date passwordExpiredAt;
    private long loginFail;
    private String authorityGroupId;
}
