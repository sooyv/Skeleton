package com.skeleton.common.token.repository;

import com.skeleton.common.entity.RoleEntity;
import org.jetbrains.annotations.NotNull;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends MongoRepository<RoleEntity, String> {
    @NotNull Optional<RoleEntity> findById(String id);
}
