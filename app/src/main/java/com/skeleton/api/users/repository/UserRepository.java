package com.skeleton.api.users.repository;

import com.skeleton.common.entity.UserEntity;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends MongoRepository<UserEntity, String> {
    boolean existsByUserId(String userId);
}
