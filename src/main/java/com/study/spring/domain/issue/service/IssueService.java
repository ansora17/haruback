package com.study.spring.domain.issue.service;

import com.study.spring.domain.issue.dto.IssueDto;
import com.study.spring.domain.issue.entity.Issue;
import com.study.spring.domain.issue.repository.IssueRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class IssueService {
    private final IssueRepository issueRepository;

    @Transactional
    public IssueDto.Response createIssue(Long adminId, IssueDto.Request request) {
        // TODO: Implement issue creation logic
        return null;
    }

    public IssueDto.Response getIssue(Long id) {
        Issue issue = issueRepository.findById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "이슈를 찾을 수 없습니다."));
        return IssueDto.Response.from(issue);
    }

    public List<IssueDto.Response> getIssuesByAdminId(Long adminId) {
        return issueRepository.findByAdminId(adminId).stream()
                .map(IssueDto.Response::from)
                .collect(Collectors.toList());
    }

    @Transactional
    public IssueDto.Response updateIssue(Long id, IssueDto.Request request) {
        // TODO: Implement issue update logic
        return null;
    }

    @Transactional
    public void deleteIssue(Long id) {
        // TODO: Implement issue deletion logic
    }
} 