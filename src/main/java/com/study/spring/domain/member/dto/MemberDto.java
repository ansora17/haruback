package com.study.spring.domain.member.dto;

import com.study.spring.domain.member.entity.ActivityLevel;
import com.study.spring.domain.member.entity.Gender;
import com.study.spring.domain.member.entity.Member;
import com.study.spring.domain.member.entity.Role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class MemberDto {
    
    // 회원가입 요청 DTO
    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class SignupRequest {
        private String email;
        private String password;
        private String nickname;
        private String name;
        private LocalDate birthAt;
        private Gender gender;
        private Float height;
        private Float weight;
        private ActivityLevel activityLevel;
        private String profileImageUrl; // 프로필 이미지 URL 추가
        
        @Override
        public String toString() {
            return "SignupRequest{" +
                    "email='" + email + '\'' +
                    ", nickname='" + nickname + '\'' +
                    ", name='" + name + '\'' +
                    ", birthAt=" + birthAt +
                    ", gender=" + gender +
                    ", height=" + height +
                    ", weight=" + weight +
                    ", activityLevel=" + activityLevel +
                    ", profileImageUrl='" + profileImageUrl + '\'' +
                    '}';
        }
    }
    
    // 회원가입 응답 DTO
    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class SignupResponse {
        private Long id;
        private String email;
        private String nickname;
        private String name;
        private LocalDate birthAt;
        private Gender gender;
        private Float height;
        private Float weight;
        private ActivityLevel activityLevel;
        private String profileImageUrl;
        private Role role;
        private LocalDateTime createdAt;
        
        public static SignupResponse from(Member member) {
            return SignupResponse.builder()
                    .id(member.getId())
                    .email(member.getEmail())
                    .nickname(member.getNickname())
                    .name(member.getName())
                    .birthAt(member.getBirthAt())
                    .gender(member.getGender())
                    .height(member.getHeight())
                    .weight(member.getWeight())
                    .activityLevel(member.getActivityLevel())
                    .profileImageUrl(member.getProfileImageUrl())
                    .role(member.getRole())
                    .createdAt(member.getCreatedAt())
                    .build();
        }
    }
    
    // 회원 정보 수정 요청 DTO
    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class UpdateRequest {
        private String email;
        private String nickname;
        private String name;
        private LocalDate birthAt;
        private Gender gender;
        private Float height;
        private Float weight;
        private ActivityLevel activityLevel;
        private String profileImageUrl;
    }
    
    // 회원 정보 조회 응답 DTO
    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class Response {
        private Long id;
        private String email;
        private String nickname;
        private String name;
        private LocalDate birthAt;
        private Gender gender;
        private Float height;
        private Float weight;
        private ActivityLevel activityLevel;
        private String profileImageUrl;
        private Role role;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;
        
        public static Response from(Member member) {
            return Response.builder()
                    .id(member.getId())
                    .email(member.getEmail())
                    .nickname(member.getNickname())
                    .name(member.getName())
                    .birthAt(member.getBirthAt())
                    .gender(member.getGender())
                    .height(member.getHeight())
                    .weight(member.getWeight())
                    .activityLevel(member.getActivityLevel())
                    .profileImageUrl(member.getProfileImageUrl())
                    .role(member.getRole())
                    .createdAt(member.getCreatedAt())
                    .updatedAt(member.getUpdatedAt())
                    .build();
        }
    }
    
    // Spring Security용 DTO
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Security implements UserDetails {
        private String email;
        private String password;
        private String nickname;
        private Role role;
        private Long memberId;
        
        // Member 엔티티를 받는 생성자 추가
        public Security(Member member) {
            this.email = member.getEmail();
            this.password = member.getPassword();
            this.nickname = member.getNickname();
            this.role = member.getRole();
            this.memberId = member.getId();
        }
        
        // UserDetails 구현 메서드들
        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
        }
        
        @Override
        public String getUsername() {
            return email; // 또는 nickname
        }
        
        @Override
        public boolean isAccountNonExpired() {
            return true;
        }
        
        @Override
        public boolean isAccountNonLocked() {
            return true;
        }
        
        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }
        
        @Override
        public boolean isEnabled() {
            return true;
        }
        
        // Member 엔티티로부터 Security 객체 생성 (정적 팩토리 메서드)
        public static Security from(Member member) {
            return new Security(member);
        }
    }
} 