package api.users.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
public class LoginDto {

    public static class LoginRequestDto {
        private String email;
        private String password;
    }

    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
     public static class LoginResponseDto {
        private long userId;
        private String email;
        private String password;
        private String username;
        // + 토큰, role, ... 추가
     }
}
