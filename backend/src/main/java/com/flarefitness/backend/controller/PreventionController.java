package com.flarefitness.backend.controller;

import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.dto.siem.PreventionDtos;
import com.flarefitness.backend.service.siem.SiemPreventionService;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/siem")
public class PreventionController {
    private final SiemPreventionService service;

    public PreventionController(SiemPreventionService service) {
        this.service = service;
    }

    @GetMapping("/signatures")
    public PageResponse<PreventionDtos.Signature> signatures(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            Authentication authentication) {
        return service.signatures(page, size, authentication);
    }

    @PostMapping("/signatures")
    public PreventionDtos.Signature create(@Valid @RequestBody PreventionDtos.CreateSignature input,
                                            Authentication authentication) {
        return service.create(input, authentication);
    }

    @PutMapping("/signatures/{id}")
    public PreventionDtos.Signature revise(@PathVariable String id, @RequestParam long version,
                                            @Valid @RequestBody PreventionDtos.CreateSignature input,
                                            Authentication authentication) {
        return service.revise(id, version, input, authentication);
    }

    @PostMapping("/signatures/{id}/test")
    public PreventionDtos.TestResult test(@PathVariable String id, @RequestParam long version,
                                          @Valid @RequestBody PreventionDtos.TestSignature input,
                                          Authentication authentication) {
        return service.test(id, version, input, authentication);
    }

    @PostMapping("/signatures/{id}/test-default")
    public PreventionDtos.TestResult testDefault(@PathVariable String id, @RequestParam long version,
                                                  Authentication authentication) {
        return service.testDefault(id, version, authentication);
    }

    @PostMapping("/signatures/{id}/activate")
    public PreventionDtos.Signature activate(@PathVariable String id, @RequestParam long version,
                                              Authentication authentication) {
        return service.activate(id, version, authentication);
    }

    @PostMapping("/signatures/{id}/disable")
    public PreventionDtos.Signature disable(@PathVariable String id, @RequestParam long version,
                                             Authentication authentication) {
        return service.disable(id, version, authentication);
    }

    @GetMapping("/prevention/status")
    public PreventionDtos.PreventionStatus status(Authentication authentication) {
        return service.status(authentication);
    }

    @GetMapping("/prevention/blocks")
    public java.util.Map<String,Object> blocks(@RequestParam(defaultValue="0") int page,
            @RequestParam(defaultValue="50") int size,Authentication authentication) {
        return service.blocksWithLedger(page,size,authentication);
    }
    @PostMapping("/prevention/blocks/{id}/revoke")
    public PreventionDtos.IpBlock revokeBlock(@PathVariable String id,
            @Valid @RequestBody SiemPreventionService.RevokeBlock request,Authentication authentication) {
        return service.revokeBlock(id,request,authentication);
    }

    @GetMapping("/ip-blocks")
    public PageResponse<PreventionDtos.IpBlock> ipBlocks(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            Authentication authentication) {
        return service.ipBlocks(page, size, authentication);
    }

    @PostMapping("/ip-blocks")
    public PreventionDtos.IpBlock createIpBlock(
            @Valid @RequestBody PreventionDtos.CreateIpBlock input,
            Authentication authentication) {
        return service.createIpBlock(input, authentication);
    }

    @PostMapping("/ip-blocks/{id}/revoke")
    public PreventionDtos.IpBlock revokeIpBlock(
            @PathVariable String id, @RequestParam long version,
            Authentication authentication) {
        return service.revokeIpBlock(id, version, authentication);
    }

    @GetMapping("/ip-intelligence")
    public List<PreventionDtos.IpIntelligence> intelligence(
            @RequestParam String ip, Authentication authentication) {
        return service.intelligence(ip, authentication);
    }

    @GetMapping("/incidents/{id}/ip-intelligence")
    public List<PreventionDtos.IpIntelligence> incidentIntelligence(
            @PathVariable String id, Authentication authentication) {
        return service.incidentIntelligence(id, authentication);
    }

    @GetMapping("/ip-intelligence/demo")
    public List<PreventionDtos.IpIntelligence> demoIntelligence(Authentication authentication) {
        return service.demoIntelligence(authentication);
    }

    @PostMapping("/ip-intelligence/demo")
    public List<PreventionDtos.IpIntelligence> seedDemoIntelligence(Authentication authentication) {
        return service.seedDemoIntelligence(authentication);
    }

    @PostMapping("/ip-intelligence/lookup")
    public java.util.Map<String, String> requestLookup(
            @RequestParam String ip,
            @RequestParam(defaultValue = "SOC_REQUEST") String reason,
            Authentication authentication) {
        return java.util.Map.of("request_id", service.requestLookup(ip, reason, authentication));
    }
}
