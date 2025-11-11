package com.skeleton.api.users.service;

import com.skeleton.api.users.dto.UserDto;
import com.skeleton.api.users.repository.UserRepository;
import com.skeleton.common.constraint.RspResultCodeEnum;
import com.skeleton.common.constraint.log.AuditLog;
import com.skeleton.common.exception.CommonException;
import com.skeleton.common.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void signUp(UserDto userDto) {
        duplicateId(userDto.getUserId());

        System.out.println("userid 확인 : "+ userDto.getUserId());

        String salt = generateSalt();
        String encodedPassword = encodePassword(userDto.getPassword(), salt);
        Date passwordExpiredAt = Date.from(
                LocalDateTime.now().plusDays(90)
                        .atZone(ZoneId.systemDefault())
                        .toInstant()
        );

        UserEntity userEntity = UserEntity.builder()
                .userId(userDto.getUserId())
                .name(userDto.getName())
                .password(encodedPassword)
                .salt(salt)
                .email(userDto.getEmail())
                .mobileNum(userDto.getMobileNum())
                .authorityGroupId("691288aa4fe98800d08b5c33")
                .passwordExpiredAt(passwordExpiredAt)
                .build();

        userRepository.save(userEntity);


    }

    public void duplicateId(String userId) {
        if (userRepository.existsByUserId(userId)) { //중복
            throw new CommonException(RspResultCodeEnum.DuplicateUser, AuditLog.OPR_ENROLL_USER, "중복된 아이디", false);
        }
    }

//    public boolean validatePassword(String raw, String encode, String salt) {
//        String hashed = encodePassword(raw, salt);
//        return hashed.equals(encode);
//    }

    private String encodePassword(String plainPassword, String salt) {
        return passwordEncoder.encode(plainPassword + salt);
    }

    private String generateSalt() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
