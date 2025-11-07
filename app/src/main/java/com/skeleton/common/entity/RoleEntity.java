package com.skeleton.common.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "roles")
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RoleEntity {
    @Id
    private String id;
    private String roleName;
    private String description;
}
