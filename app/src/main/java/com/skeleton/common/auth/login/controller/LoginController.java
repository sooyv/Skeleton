package com.skeleton.common.auth.login.controller;

import com.skeleton.common.auth.login.dto.LoginRequest;
import com.skeleton.common.auth.login.dto.LoginResponse;
import com.skeleton.common.auth.login.LoginService;
import com.skeleton.common.base.BaseApiController;
import com.skeleton.common.constraint.log.AuditLog;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
public class LoginController extends BaseApiController{
    private final LoginService loginService;

    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        LoginResponse response = loginService.login(loginRequest);
        System.out.println("login controller");
        return rspSuccess(AuditLog.OPR_LOGIN_USER, response, false);
    }
}
