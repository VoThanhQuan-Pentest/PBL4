package com.flarefitness.backend.controller;

import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.dto.siem.PostloginDtos;
import com.flarefitness.backend.service.siem.PostloginSocService;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/siem")
public class PostloginSocController {
    private final PostloginSocService service;
    public PostloginSocController(PostloginSocService service) { this.service=service; }
    @GetMapping("/postlogin-policy")
    public PostloginDtos.PolicyStatus policy() { return service.status(); }
    @GetMapping("/postlogin-decisions")
    public PageResponse<PostloginDtos.Summary> list(@RequestParam(required=false) String incidentId,
            @RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="50") int size) {
        return service.list(incidentId,page,size);
    }
    @GetMapping("/postlogin-decisions/{id}")
    public PostloginDtos.Detail detail(@PathVariable String id) { return service.detail(id); }
    @PostMapping("/postlogin-decisions/{id}/release")
    public PostloginDtos.Detail release(@PathVariable String id,@Valid @RequestBody PostloginDtos.Release body,Authentication authentication) {
        return service.release(id,body,authentication);
    }
    @PostMapping("/postlogin-decisions/{id}/review")
    public PostloginDtos.Detail review(@PathVariable String id,@Valid @RequestBody PostloginDtos.ReviewRequest body,Authentication authentication) {
        return service.review(id,body,authentication);
    }
}
