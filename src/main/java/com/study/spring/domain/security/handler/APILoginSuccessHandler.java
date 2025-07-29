package com.study.spring.domain.security.handler;

import com.study.spring.domain.member.dto.MemberDto;
import com.study.spring.domain.member.entity.Member;
import com.study.spring.domain.member.repository.MemberRepository;
import com.study.spring.domain.security.util.JWTUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class APILoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;
    private final MemberRepository memberRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        log.info("################################");
        log.info(authentication.getPrincipal());
        log.info("################################");
        
        // MemberDto.Security로 캐스팅 (CustomUserDetailsService에서 반환하는 타입)
        MemberDto.Security memberSecurity = (MemberDto.Security) authentication.getPrincipal();
        
        // DB에서 실제 Member 엔티티 조회 (추가 정보 필요시)
        Member member = memberRepository.findById(memberSecurity.getMemberId())
            .orElseThrow(() -> new RuntimeException("Member not found"));
        
        // 모든 사용자 정보를 claims에 포함
        Map<String, Object> claims = new HashMap<>();
        claims.put("memberId", memberSecurity.getMemberId());
        claims.put("email", memberSecurity.getEmail());
        claims.put("nickname", memberSecurity.getNickname());
        claims.put("name", member.getName());
        claims.put("birthAt", member.getBirthAt().toString()); // LocalDate -> String 변환
        claims.put("gender", member.getGender().name());
        claims.put("height", member.getHeight());
        claims.put("weight", member.getWeight());
        claims.put("activityLevel", member.getActivityLevel().name());
        claims.put("role", memberSecurity.getRole().name());
        claims.put("profileImageUrl", member.getProfileImageUrl());
        claims.put("recommendedCalories", member.calculateRecommendedCalories());
        
        // 토큰 생성
        String accessToken = jwtUtil.generateToken(claims, 60); // 60분
        String refreshToken = jwtUtil.generateToken(claims, 60*24*7); // 7일
        
        // claims에 토큰도 추가
        claims.put("accessToken", accessToken);
        claims.put("refreshToken", refreshToken);
        
        // refresh token을 DB에 저장
        member.updateRefreshToken(refreshToken);
        memberRepository.save(member);
        
        // JSON 형식으로 전체 정보 응답
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonStr = objectMapper.writeValueAsString(claims);
            
            response.setContentType("application/json;charset=UTF-8");
            PrintWriter printWriter = response.getWriter();
            printWriter.println(jsonStr);
            printWriter.close();
            
            log.info("Login success with all user data: {}", memberSecurity.getNickname());
        } catch (Exception e) {
            log.error("Error creating JSON response: ", e);
            throw e;
        }
    }
}
