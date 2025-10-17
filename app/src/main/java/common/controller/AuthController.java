package common.controller;


import common.DTO.UserDto;
import common.entity.User;
import common.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;

    // 회원가입
    @PostMapping("/sign-up")
    public ResponseEntity<User> signUp(@Valid @RequestBody UserDto userDto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(this.userService.signUp(userDto));

    }

}
