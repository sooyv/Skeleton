package com.skeleton.common.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@Document(collection = "roles")
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RoleEntity {
    @Id
    private String id;
    private List<AuthRoleEnum> roles;
    private String description;
}
