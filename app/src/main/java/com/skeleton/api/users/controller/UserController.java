package com.skeleton.api.users.controller;


import com.skeleton.api.users.dto.UserDto;
import com.skeleton.api.users.service.UserService;
import com.skeleton.common.base.BaseApiController;
import com.skeleton.common.constraint.log.AuditLog;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class UserController extends BaseApiController {
    private final UserService userService;

    // 회원가입
    @RequestMapping(value = "/signup", method = RequestMethod.POST)
    public ResponseEntity<?> signUp(@Valid @RequestBody UserDto userDto) {
        userService.signUp(userDto);
        // 성공시 응답값, 어떤 객체를 던질건지, isLog는 카프카에 값을 보낼지 안닐지 설정하는 부분
        return rspSuccess(AuditLog.OPR_ENROLL_USER, userDto, false);
    }

}
