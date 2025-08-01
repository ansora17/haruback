package com.study.spring.domain.member.repository;

import com.study.spring.domain.member.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {
    
    // 이메일로 회원 조회
    Optional<Member> findByEmail(String email);
    
    // 닉네임으로 회원 조회
    Optional<Member> findByNickname(String nickname);
    
    // 이메일 존재 여부 확인
    boolean existsByEmail(String email);
    
    // 닉네임 존재 여부 확인
    boolean existsByNickname(String nickname);
    
    // 이름과 이메일로 회원 조회
    Optional<Member> findByNameAndEmail(String name, String email);
    
    // 닉네임으로 닉네임 찾기
    @Query("SELECT m.nickname FROM Member m WHERE m.name = :name AND m.email = :email")
    Optional<String> findNicknameByNameAndEmail(@Param("name") String name, @Param("email") String email);
    
    // 회원 검색 (이름, 닉네임, 이메일로 검색)
    @Query("SELECT m FROM Member m WHERE m.name LIKE %:query% OR m.nickname LIKE %:query% OR m.email LIKE %:query%")
    List<Member> searchMembers(@Param("query") String query);
    
    // 활성 회원만 조회
    @Query("SELECT m FROM Member m WHERE m.role != 'DELETED'")
    List<Member> findActiveMembers();
} 