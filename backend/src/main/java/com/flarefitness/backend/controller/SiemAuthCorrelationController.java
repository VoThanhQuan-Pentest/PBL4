package com.flarefitness.backend.controller;

import com.flarefitness.backend.service.siem.SiemAuthCorrelationService;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/siem/auth-correlation/policy")
public class SiemAuthCorrelationController {
    private final SiemAuthCorrelationService service;
    public SiemAuthCorrelationController(SiemAuthCorrelationService service){this.service=service;}
    @GetMapping public SiemAuthCorrelationService.Policy get(){return service.policy();}
    @GetMapping("/history") public java.util.List<java.util.Map<String,Object>> history(){return service.policyHistory();}
    @PutMapping public SiemAuthCorrelationService.Policy change(@Valid @RequestBody SiemAuthCorrelationService.Change request,Authentication authentication){return service.change(request,authentication);}
}
