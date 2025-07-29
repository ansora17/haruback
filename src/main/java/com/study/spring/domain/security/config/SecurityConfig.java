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

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Log4j2
public class SecurityConfig {
    
    private final JWTUtil jwtUtil;
    private final MemberRepository memberRepository;
    private final CustomUserDetailsService customUserDetailsService; // 추가
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        
        log.info("--------------------- security config ---------------------");
        
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            
//            // UserDetailsService 명시적 설정
//            .userDetailsService(customUserDetailsService)
            
            // FormLogin 설정
            .formLogin(config -> {
                config.loginPage("/api/members/login");
                config.loginProcessingUrl("/api/members/login"); // 추가
                config.usernameParameter("nickname"); // 추가 (기본값은 username)
                config.passwordParameter("password");
                config.successHandler(new APILoginSuccessHandler(jwtUtil, memberRepository));
                config.failureHandler(new APILoginFailHandler());
            });
            
            
//            .addFilterBefore(new JWTCheckFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class)
//            .exceptionHandling(ex -> ex.accessDeniedHandler(new CustomAccessDeniedHandler()));
//        
        return http.build();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        configuration.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }
}