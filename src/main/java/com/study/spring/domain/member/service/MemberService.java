package com.study.spring.domain.member.service;

import com.study.spring.domain.member.dto.MemberDto;
import com.study.spring.domain.member.entity.Member;
import com.study.spring.domain.member.entity.Role;
import com.study.spring.domain.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberService {
    
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    
    // 회원가입
    @Transactional
    public MemberDto.SignupResponse signup(MemberDto.SignupRequest request) {
        System.out.println("📥 회원가입 요청: " + request.getEmail());
        
        // 입력값 검증
        validateSignupRequest(request);
        
        // 이메일 중복 확인
        if (memberRepository.existsByEmail(request.getEmail())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 존재하는 이메일입니다.");
        }
        
        // 닉네임 중복 확인
        if (memberRepository.existsByNickname(request.getNickname())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 존재하는 닉네임입니다.");
        }
        
        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(request.getPassword());
        System.out.println("🔐 비밀번호 암호화 완료");
        
        // Member 엔티티 생성
        Member member = Member.createMember()
                .email(request.getEmail())
                .password(encodedPassword)
                .nickname(request.getNickname())
                .name(request.getName())
                .birthAt(request.getBirthAt())
                .gender(request.getGender())
                .height(request.getHeight())
                .weight(request.getWeight())
                .activityLevel(request.getActivityLevel())
                .profileImageUrl(request.getProfileImageUrl()) // 프로필 이미지 URL 설정
                .role(Role.USER)
                .build();
        
        Member savedMember = memberRepository.save(member);
        System.out.println("✅ 회원가입 완료: " + savedMember.getEmail());
        
        return MemberDto.SignupResponse.from(savedMember);
    }
    
    // 회원가입 요청 검증
    private void validateSignupRequest(MemberDto.SignupRequest request) {
        if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "이메일은 필수입니다.");
        }
        
        if (request.getPassword() == null || request.getPassword().trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "비밀번호는 필수입니다.");
        }
        
        if (request.getPassword().length() < 6) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "비밀번호는 최소 6자 이상이어야 합니다.");
        }
        
        if (request.getNickname() == null || request.getNickname().trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "닉네임은 필수입니다.");
        }
        
        if (request.getName() == null || request.getName().trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "이름은 필수입니다.");
        }
        
        if (request.getBirthAt() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "생년월일은 필수입니다.");
        }
        
        if (request.getHeight() == null || request.getHeight() <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "키는 필수이며 0보다 커야 합니다.");
        }
        
        if (request.getWeight() == null || request.getWeight() <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "체중은 필수이며 0보다 커야 합니다.");
        }
        
        if (request.getActivityLevel() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "활동 수준은 필수입니다.");
        }
        
        // profileImageUrl은 선택사항이므로 검증하지 않음
    }
    
    // 회원 정보 조회
    public MemberDto.Response getMember(Long id) {
        Member member = memberRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));
        
        return MemberDto.Response.from(member);
    }
    
    // 이메일로 회원 조회
    public MemberDto.Response getMemberByEmail(String email) {
        Member member = memberRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));
        
        return MemberDto.Response.from(member);
    }
    
    // 닉네임으로 회원 조회
    public MemberDto.Response getMemberByNickname(String nickname) {
        Member member = memberRepository.findByNickname(nickname)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));
        
        return MemberDto.Response.from(member);
    }
    
    // 회원 정보 수정
    @Transactional
    public MemberDto.Response updateMember(Long id, MemberDto.UpdateRequest request) {
        Member member = memberRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));
        
        // 이메일 변경 시 중복 확인
        if (request.getEmail() != null && !member.getEmail().equals(request.getEmail()) && 
            memberRepository.existsByEmail(request.getEmail())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 존재하는 이메일입니다.");
        }
        
        // 닉네임 변경 시 중복 확인
        if (request.getNickname() != null && !member.getNickname().equals(request.getNickname()) && 
            memberRepository.existsByNickname(request.getNickname())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 존재하는 닉네임입니다.");
        }
        
        // Member 엔티티 업데이트
        Member updatedMember = member.toBuilder()
                .email(request.getEmail() != null ? request.getEmail() : member.getEmail())
                .nickname(request.getNickname() != null ? request.getNickname() : member.getNickname())
                .name(request.getName() != null ? request.getName() : member.getName())
                .birthAt(request.getBirthAt() != null ? request.getBirthAt() : member.getBirthAt())
                .gender(request.getGender() != null ? request.getGender() : member.getGender())
                .height(request.getHeight() != null ? request.getHeight() : member.getHeight())
                .weight(request.getWeight() != null ? request.getWeight() : member.getWeight())
                .activityLevel(request.getActivityLevel() != null ? request.getActivityLevel() : member.getActivityLevel())
                .profileImageUrl(request.getProfileImageUrl() != null ? request.getProfileImageUrl() : member.getProfileImageUrl())
                .build();
        
        Member savedMember = memberRepository.save(updatedMember);
        return MemberDto.Response.from(savedMember);
    }
    
    // 비밀번호 변경
    @Transactional
    public void updatePassword(Long id, String newPassword) {
        // 비밀번호 검증
        validatePassword(newPassword);
        
        Member member = memberRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));
        
        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(newPassword);
        System.out.println("🔐 비밀번호 변경 - 암호화 완료");
        
        Member updatedMember = member.toBuilder()
                .password(encodedPassword)
                .build();
        
        memberRepository.save(updatedMember);
        System.out.println("✅ 비밀번호 변경 완료: " + member.getEmail());
    }
    
    // 비밀번호 검증
    private void validatePassword(String password) {
        if (password == null || password.trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "비밀번호는 필수입니다.");
        }
        
        if (password.length() < 6) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "비밀번호는 최소 6자 이상이어야 합니다.");
        }
        
        // 추가적인 비밀번호 정책 검증 (선택사항)
        if (!password.matches(".*[A-Za-z].*")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "비밀번호는 영문자를 포함해야 합니다.");
        }
        
        if (!password.matches(".*[0-9].*")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "비밀번호는 숫자를 포함해야 합니다.");
        }
    }
    
    // 회원 탈퇴
    @Transactional
    public void deleteMember(Long id) {
        Member member = memberRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));
        
        memberRepository.delete(member);
    }
    
    // 이메일 중복 확인
    public boolean existsByEmail(String email) {
        return memberRepository.existsByEmail(email);
    }
    
    // 닉네임 중복 확인
    public boolean existsByNickname(String nickname) {
        return memberRepository.existsByNickname(nickname);
    }
    
    // 회원 검색
    public List<MemberDto.Response> searchMembers(String query) {
        List<Member> members = memberRepository.searchMembers(query);
        return members.stream()
                .map(MemberDto.Response::from)
                .toList();
    }
    
    // 닉네임 찾기
    public Optional<String> findNicknameByNameAndEmail(String name, String email) {
        return memberRepository.findNicknameByNameAndEmail(name, email);
    }
    
    // 비밀번호 재설정 요청
    public boolean requestPasswordReset(String email) {
        Optional<Member> memberOpt = memberRepository.findByEmail(email);
        
        if (memberOpt.isPresent()) {
            Member member = memberOpt.get();
            
            // TODO: 실제 이메일 발송 로직 구현
            // 1. 임시 비밀번호 생성
            // 2. 임시 비밀번호로 업데이트
            // 3. 이메일 발송
            
            System.out.println("📧 비밀번호 재설정 이메일 발송: " + email);
            System.out.println("📧 회원 정보: " + member.getNickname());
            
            return true;
        }
        
        return false;
    }
    
    // 비밀번호 확인 (로그인 시 사용)
    public boolean verifyPassword(String email, String rawPassword) {
        Member member = memberRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));
        
        return passwordEncoder.matches(rawPassword, member.getPassword());
    }
    
    // 비밀번호 확인 (닉네임으로)
    public boolean verifyPasswordByNickname(String nickname, String rawPassword) {
        Member member = memberRepository.findByNickname(nickname)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));
        
        return passwordEncoder.matches(rawPassword, member.getPassword());
    }
} 