package api.users.service;

import api.users.dto.UserDto;

public interface UserService {
    void signUp(UserDto userDto);
}
