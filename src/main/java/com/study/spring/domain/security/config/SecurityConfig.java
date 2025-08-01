package com.study.spring.domain.security.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

import java.util.Arrays;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.study.spring.domain.security.handler.APILoginFailHandler;
import com.study.spring.domain.security.handler.APILoginSuccessHandler;
import com.study.spring.domain.security.handler.CustomAccessDeniedHandler;
import com.study.spring.domain.security.service.CustomUserDetailsService;
import com.study.spring.domain.security.util.JWTCheckFilter;
import com.study.spring.domain.security.util.JWTUtil;
import com.study.spring.domain.member.repository.MemberRepository;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Log4j2
public class SecurityConfig {

    private final JWTUtil jwtUtil;
    private final MemberRepository memberRepository;
    private final CustomUserDetailsService customUserDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        
        log.info("--------------------- security config - 완전 오픈 모드 ---------------------");
        
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            
            // UserDetailsService 설정 (로그인용)
            .userDetailsService(customUserDetailsService)
            
            // FormLogin 설정 (로그인은 유지)
            .formLogin(config -> {
                config.loginPage("/api/members/login");
                config.loginProcessingUrl("/api/members/login");
                config.usernameParameter("nickname");
                config.passwordParameter("password");
                config.successHandler(new APILoginSuccessHandler(jwtUtil, memberRepository));
                config.failureHandler(new APILoginFailHandler());
            })
            
            // 🔥 모든 요청 완전 허용 - 인증 없이 모든 API 접근 가능
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll() // 모든 요청 허용!
            );
            
            // JWT 필터와 예외 처리는 주석 처리 (완전 오픈)
            // .addFilterBefore(new JWTCheckFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class)
            // .exceptionHandling(ex -> ex.accessDeniedHandler(new CustomAccessDeniedHandler()));
        
        return http.build();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // 🌐 모든 도메인 허용
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        
        configuration.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"
        ));
        
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }
}