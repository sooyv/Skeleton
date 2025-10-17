package common.entity;

import lombok.Builder;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Set;

@Document(collection = "users")
@Builder
@Getter
public class User {
    @Id
    private String id;

    private String email;
    private String password;
    private String name;
    private Set<String> roles;

}
