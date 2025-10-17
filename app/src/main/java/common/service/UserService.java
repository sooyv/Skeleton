package common.service;

import common.DTO.UserDto;
import common.entity.User;
import common.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User signUp(UserDto userDto) {
        userRepository.findByEmail(userDto.getEmail()).ifPresent(user ->
                new RuntimeException(user.getId() + "는 이미 존재하는 계정입니다."));

        User user = User.builder()
                .email(userDto.getEmail())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .name(userDto.getUsername())
                .roles(Set.of("USER"))
                .build();

        return userRepository.save(user);
    }
}
