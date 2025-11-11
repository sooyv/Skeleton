package com.skeleton.common.auth.login.repository;

import com.skeleton.common.entity.UserTokenEntity;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface LoginTokenRepository extends MongoRepository<UserTokenEntity, String> {

    Optional<UserTokenEntity> findTokenByUserId(String userId);

    Optional<UserTokenEntity> findByAccessToken(String jwt);

    void deleteByUserId(String userId);
}
