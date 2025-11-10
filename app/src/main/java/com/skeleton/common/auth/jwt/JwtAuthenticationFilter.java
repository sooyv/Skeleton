package com.skeleton.common.auth.jwt;

import com.skeleton.common.auth.login.LoginService;
import com.skeleton.common.auth.login.LoginToken;
import com.skeleton.common.exception.CommonException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final LoginService loginService;
    public JwtAuthenticationFilter(LoginService loginService) {
        this.loginService = loginService;
    }

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest req, @NotNull HttpServletResponse resp,
                                    @NotNull FilterChain chain) throws ServletException, IOException {
        log.info("인증 필터 진입 doFilterInternal");

        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;     // 필터체인 중단
        }

        LoginToken loginToken = null;


        try {
            // 토큰이 있을 경우!!!!!
            loginToken = loginService.verifyJwt(authHeader);

            // JWT 가 갱신되었을 수도 있기 때문에 다시 꺼내서 헤더에 담기


            // SecurityContextHolder는 요청(Request) 단위로만 인증 상태를 유지
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(loginToken, loginToken.getUserEntity(), loginToken.getAuthorities())
            );

            if (loginToken != null
                    && loginToken.getJwt() != null) {
                resp.setHeader("X-Refreshed-JWT", "Bearer " + loginToken.getJwt());
            }

            chain.doFilter(req, resp);

        } catch (Exception ex) {
            req.setAttribute("exception", ex);
            System.out.println("doFilterInternal exception: " + ex);
        }
    }
}
