package api.users.repository;

import common.entity.UserEntity;
import org.springframework.data.mongodb.repository.MongoRepository;


public interface UserRepository extends MongoRepository<UserEntity, String> {
    boolean existsByUserId(String userId);
}
