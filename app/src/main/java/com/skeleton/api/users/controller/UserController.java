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
    public ResponseEntity<?> signUp(
            @Valid @RequestBody UserDto userDto
    ) {
        log.info("aaa");
        userService.signUp(userDto);
        return rspSuccess(AuditLog.OPR_LOGIN_USER, userDto, false);
    }

}
