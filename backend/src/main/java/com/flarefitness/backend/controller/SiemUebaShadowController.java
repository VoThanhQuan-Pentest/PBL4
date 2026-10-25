package com.flarefitness.backend.controller;

import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.service.siem.SiemUebaShadowService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/siem/ueba/shadow-runs")
public class SiemUebaShadowController {
    private final SiemUebaShadowService shadows;
    public SiemUebaShadowController(SiemUebaShadowService shadows) { this.shadows = shadows; }
    @PostMapping @ResponseStatus(HttpStatus.ACCEPTED)
    public SiemDtos.UebaShadowRun start(@Valid @RequestBody SiemDtos.StartUebaShadow request, Authentication authentication) {
        return shadows.start(request, authentication);
    }
    @GetMapping
    public PageResponse<SiemDtos.UebaShadowRun> list(@RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size, Authentication authentication) {
        return shadows.list(page, size, authentication);
    }
    @GetMapping("/{id}")
    public SiemDtos.UebaShadowRun get(@PathVariable String id, Authentication authentication) { return shadows.get(id, authentication); }
}
