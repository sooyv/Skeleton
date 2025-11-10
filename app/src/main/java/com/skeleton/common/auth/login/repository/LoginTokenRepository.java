package com.skeleton.common.auth.login.repository;

import com.skeleton.common.entity.LoginTokenEntity;
import org.apache.el.parser.Token;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface LoginTokenRepository extends MongoRepository<LoginTokenEntity, String> {

    Optional<LoginTokenEntity> findTokenByUserId(String userId);

    Optional<LoginTokenEntity> findByAccessToken(String jwt);

}
