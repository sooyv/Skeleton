package com.skeleton.common.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.skeleton.common.auth.jwt.JwtAuthenticationFilter;
import com.skeleton.common.constraint.RspResultCodeEnum;
import com.skeleton.common.exception.CommonException;
import com.skeleton.common.response.ResponseDto;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.IOException;
import java.util.List;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig implements WebMvcConfigurer {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .cors(x -> x.configurationSource(corsConfigurationSource()))
                .csrf(CsrfConfigurer::disable)
//                .formLogin(AbstractHttpConfigurer::disable)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(authenticationEntryPoint()) //401
                        .accessDeniedHandler(accessDeniedHandler()) //403
                )
                .authorizeHttpRequests(request -> {
                    request
                            // Swagger 등 인증 없이 허용하는 경로 처리
                            .requestMatchers("/api/**").permitAll()
                            // 그 외는 인증 필요
                            .anyRequest().authenticated();
                });

        return http.build();
    }

    @Bean
    public HttpFirewall allowUrlEncodedSlashHttpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowUrlEncodedSlash(true);
        firewall.setAllowSemicolon(true);
        return firewall;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(List.of("*"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setExposedHeaders(List.of("X-Refreshed-JWT"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> {
            CommonException ex = (CommonException) request.getAttribute("exception");
            if (ex == null) {
                // 예외 객체가 없으므로 기본 에러 처리(401/403 이 아닌 에러 404 처리)
                log.error("No CommonPortalException found in request attributes");
                RspResultCodeEnum resultCodeEnum = RspResultCodeEnum.Undefined;
                ResponseDto rspDtos = new ResponseDto(resultCodeEnum, "오류", null, null);
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                try {
                    ObjectMapper objectMapper = new ObjectMapper();
                    response.getWriter().write(objectMapper.writeValueAsString(rspDtos));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                return;
            }
            log.error("[Filter error] Invalid parameter, response:{}, msg:{}, detail:{}", ex.getCode(), ex.getMessage(), ex.getDetail());
            RspResultCodeEnum resultCodeEnum = ex.getCode();
            ResponseDto rspDtos = new ResponseDto(resultCodeEnum, "오류", null, null);
            ObjectMapper objectMapper = new ObjectMapper();
            response.setStatus(resultCodeEnum.getStatus().value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            try {
                response.getWriter().write(objectMapper.writeValueAsString(rspDtos));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        };
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            log.warn("Access denied: {}", accessDeniedException.getMessage());
            RspResultCodeEnum resultCodeEnum = RspResultCodeEnum.UnAuthorized;
            ResponseDto rspDtos = new ResponseDto(resultCodeEnum, "오류", null, null);
            // 여기서도 CommonException 등을 사용할 수 있음
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                response.getWriter().write(objectMapper.writeValueAsString(rspDtos));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
