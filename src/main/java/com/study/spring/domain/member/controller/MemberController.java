package com.study.spring.domain.member.controller;

import com.study.spring.domain.member.dto.MemberDto;
import com.study.spring.domain.member.entity.Member;
import com.study.spring.domain.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/members")
@RequiredArgsConstructor
public class MemberController {
    
    private final MemberService memberService;
    
    
    
    // 테스트용 간단한 엔드포인트
    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("Member API is working!");
    }
    
    // 회원가입
    @PostMapping("/signup")
    public ResponseEntity<MemberDto.SignupResponse> signup(@RequestBody MemberDto.SignupRequest request) {
        System.out.println("📥 회원가입 API 호출됨!");
        System.out.println("📥 요청 데이터: " + request);
        System.out.println("📥 이메일: " + request.getEmail());
        
        try {
            MemberDto.SignupResponse response = memberService.signup(request);
            System.out.println("✅ 회원가입 성공: " + response.getEmail());
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (Exception e) {
            System.out.println("❌ 회원가입 실패: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
    
    // ID로 회원 조회
    @GetMapping("/{id}")
    public ResponseEntity<MemberDto.Response> getMember(@PathVariable("id") Long id) {
        MemberDto.Response response = memberService.getMember(id);
        return ResponseEntity.ok(response);
    }
    
    // 이메일로 회원 조회
    @GetMapping("/email/{email}")
    public ResponseEntity<MemberDto.Response> getMemberByEmail(@PathVariable("email") String email) {
        MemberDto.Response response = memberService.getMemberByEmail(email);
        return ResponseEntity.ok(response);
    }
    
    // 닉네임으로 회원 조회
    @GetMapping("/nickname/{nickname}")
    public ResponseEntity<MemberDto.Response> getMemberByNickname(@PathVariable("nickname") String nickname) {
        MemberDto.Response response = memberService.getMemberByNickname(nickname);
        return ResponseEntity.ok(response);
    }
    
    // 회원 정보 수정
    @PutMapping("/{id}")
    public ResponseEntity<MemberDto.Response> updateMember(
            @PathVariable("id") Long id,
            @RequestBody MemberDto.UpdateRequest request) {
        MemberDto.Response response = memberService.updateMember(id, request);
        return ResponseEntity.ok(response);
    }
    
    
    
    
    // 회원 탈퇴
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteMember(@PathVariable("id") Long id) {
        memberService.deleteMember(id);
        return ResponseEntity.noContent().build();
    }
    
    // 이메일 중복 확인
    @GetMapping("/check-email")
    public ResponseEntity<Boolean> checkEmailExists(@RequestParam("email") String email) {
        boolean exists = memberService.existsByEmail(email);
        return ResponseEntity.ok(exists);
    }
    
    // 닉네임 중복 확인
    @GetMapping("/check-nickname")
    public ResponseEntity<Boolean> checkNicknameExists(@RequestParam("nickname") String nickname) {
        boolean exists = memberService.existsByNickname(nickname);
        return ResponseEntity.ok(exists);
    }
    
    // 회원 검색
    @GetMapping("/search")
    public ResponseEntity<List<MemberDto.Response>> searchMembers(@RequestParam("query") String query) {
        List<MemberDto.Response> members = memberService.searchMembers(query);
        return ResponseEntity.ok(members);
    }
    
    // 닉네임 찾기
    @PostMapping("/find-nickname")
    public ResponseEntity<?> findNickname(@RequestBody Map<String, String> payload) {
        String name = payload.get("name");
        String email = payload.get("email");
        
        Optional<String> nickname = memberService.findNicknameByNameAndEmail(name, email);
        
        if (nickname.isPresent()) {
            return ResponseEntity.ok(Map.of("nickname", nickname.get()));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "해당 정보로 가입된 회원을 찾을 수 없습니다."));
        }
    }
    
    // 비밀번호 재설정 요청
    @PostMapping("/reset-password")
    public ResponseEntity<?> requestPasswordReset(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        boolean exists = memberService.requestPasswordReset(email);
        
        if (exists) {
            return ResponseEntity.ok(Map.of("message", "비밀번호 재설정 이메일이 발송되었습니다."));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "해당 이메일로 가입된 회원을 찾을 수 없습니다."));
        }
    }
    
    // 비밀번호 확인 (이메일로)
    @PostMapping("/verify-password")
    public ResponseEntity<?> verifyPassword(@RequestBody Map<String, String> payload) {
        String email = payload.get("email");
        String password = payload.get("password");
        
        try {
            boolean isValid = memberService.verifyPassword(email, password);
            return ResponseEntity.ok(Map.of("valid", isValid));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "회원을 찾을 수 없습니다."));
        }
    }
    
    // 비밀번호 확인 (닉네임으로)
    @PostMapping("/verify-password-nickname")
    public ResponseEntity<?> verifyPasswordByNickname(@RequestBody Map<String, String> payload) {
        String nickname = payload.get("nickname");
        String password = payload.get("password");
        
        try {
            boolean isValid = memberService.verifyPasswordByNickname(nickname, password);
            return ResponseEntity.ok(Map.of("valid", isValid));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "회원을 찾을 수 없습니다."));
        }
    }
    
   
    
    
} 