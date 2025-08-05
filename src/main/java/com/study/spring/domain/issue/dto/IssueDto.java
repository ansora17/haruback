package com.study.spring.domain.issue.dto;

import com.study.spring.domain.issue.entity.Issue;
import com.study.spring.domain.member.entity.Role;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.time.LocalDateTime;

public class IssueDto {

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Request {
        private String title;
        private String content;
        private String reference;
    }

    @Getter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Response {
        private Long id;
        private String title;
        private String content;
        private String reference;
        private Long adminId;
        private Role role;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;

        public static Response from(Issue issue) {
            return Response.builder()
                    .id(issue.getId())
                    .title(issue.getTitle())
                    .content(issue.getContent())
                    .reference(issue.getReference())
                    .adminId(issue.getAdmin().getId())
                    .role(issue.getRole())
                    .createdAt(issue.getCreatedAt())
                    .updatedAt(issue.getUpdatedAt())
                    .build();
        }
    }
} 