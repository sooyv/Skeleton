package api.users.controller;


import api.users.dto.UserDto;
import api.users.service.UserService;
import common.base.BaseApiController;
import common.constraint.log.AuditLog;
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
    @RequestMapping(value = "/sign-up", method = RequestMethod.POST)
    public ResponseEntity<?> signUp(
            @Valid @RequestBody UserDto userDto
    ) {
        userService.signUp(userDto);
        return rspSuccess(AuditLog.OPR_LOGIN_USER, userDto, false);
    }

}
