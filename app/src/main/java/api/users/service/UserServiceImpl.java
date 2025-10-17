package api.users.service;

import api.users.dto.UserDto;
import api.users.repository.UserRepository;
import common.constraint.RspResultCodeEnum;
import common.constraint.log.AuditLog;
import common.exception.CommonException;
import common.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void signUp(UserDto userDto) {
        duplicateId(userDto.getUserId());


        String salt = generateSalt();
        String encodedPassword = encodePassword(userDto.getPassword(), salt);

        UserEntity userEntity = UserEntity.builder()
                .userId(userDto.getUserId())
                .name(userDto.getName())
                .password(encodedPassword)
                .salt(salt)
                .email(userDto.getEmail())
                .mobileNum(userDto.getMobileNum())
//                .authorityGroupId("DEFAULT")
                .build();

        userRepository.save(userEntity);
    }

    public void duplicateId(String userId) {
        if (userRepository.existsByUserId(userId)) { //중복
            throw new CommonException(RspResultCodeEnum.DuplicateUser, AuditLog.OPR_ENROLL_USER, "중복된 아이디", false);
        }
    }

    private String encodePassword(String plainPassword, String salt) {
        return passwordEncoder.encode(plainPassword + salt);
    }

    private String generateSalt() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
