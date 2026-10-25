package com.flarefitness.backend.controller;

import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.service.siem.*;
import jakarta.validation.Valid;
import java.time.LocalDateTime;
import java.util.*;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/siem")
public class SiemWorkspaceController {
    private final SiemEvidenceService evidence;
    private final SiemElasticGateway elastic;
    @org.springframework.beans.factory.annotation.Autowired
    private SiemAuthCorrelationService authCorrelation;
    @org.springframework.beans.factory.annotation.Autowired
    private SiemAuthShadowService authShadow;
    private final SiemWorkspaceService workspace;
    private final SiemContainmentService containment;
    private final SiemStatusService status;
    private final SiemUebaModelService model;
    private final SiemIncidentService workflow;
    private final SiemPreventionService prevention;
    private final PostloginSocService postlogin;
    private final SiemInvestigationService investigation;
    public SiemWorkspaceController(SiemEvidenceService evidence,SiemWorkspaceService workspace,SiemContainmentService containment,
            SiemStatusService status,SiemUebaModelService model,SiemIncidentService workflow,SiemPreventionService prevention,PostloginSocService postlogin,SiemElasticGateway elastic,SiemInvestigationService investigation) {
        this.evidence=evidence;this.workspace=workspace;this.containment=containment;this.status=status;this.model=model;this.workflow=workflow;this.prevention=prevention;this.postlogin=postlogin;this.elastic=elastic;this.investigation=investigation;
    }
    @GetMapping("/workspace")
    public Map<String,Object> workspace(Authentication authentication) {
        return Map.of("capabilities",workflow.capabilities(authentication),"pipeline",status.status(),"model",model.status(),
                "postlogin",postlogin.status(),"policy",prevention.status(authentication),"model_scope","PROJECT_LIMITED","maximum_hold_seconds",600,"auth_correlation",authCorrelation.policy(),"auth_shadow",authShadow.status());
    }
    @GetMapping("/geo/summary")
    public SiemElasticGateway.GeoSummary geoSummary(
            @RequestParam @DateTimeFormat(iso=DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso=DateTimeFormat.ISO.DATE_TIME) LocalDateTime to) { return elastic.geoSummary(from,to); }
    @GetMapping("/evidence")
    public SiemEvidenceService.Page evidence(
            @RequestParam @DateTimeFormat(iso=DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso=DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(required=false) String dataset,@RequestParam(required=false) String traceId,
            @RequestParam(required=false) String ip,@RequestParam(required=false) String accountId,
            @RequestParam(required=false) String cursor,@RequestParam(defaultValue="50") int size) {
        return evidence.search(new SiemEvidenceService.Filter(from,to,dataset,traceId,ip,accountId,size),cursor,null,Set.of());
    }
    @GetMapping("/incidents/{id}/evidence")
    public SiemEvidenceService.Page incidentEvidence(@PathVariable String id,@RequestParam(required=false) String cursor,@RequestParam(defaultValue="50") int size) {
        return workspace.incidentEvidence(id,cursor,size);
    }
    @GetMapping("/shadow-assessments")
    public List<Map<String,Object>> shadowAssessments(@RequestParam(required=false) String incidentId,@RequestParam(required=false) String accountId,
            @RequestParam @DateTimeFormat(iso=DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso=DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,@RequestParam(defaultValue="50") int size) {
        return authShadow.list(incidentId,accountId,from,to,size);
    }
    @GetMapping("/investigation-metrics")
    public SiemInvestigationService.Metrics metrics(
            @RequestParam @DateTimeFormat(iso=DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso=DateTimeFormat.ISO.DATE_TIME) LocalDateTime to) {return investigation.metrics(from,to);}
    @GetMapping("/incidents/{id}/investigation-summary")
    public SiemInvestigationService.Summary summary(@PathVariable String id,
            @RequestParam(defaultValue="false") boolean includeEventTime) {return investigation.summary(id,includeEventTime);}
    @GetMapping("/incidents/{id}/timeline")
    public SiemInvestigationService.Timeline timeline(@PathVariable String id,@RequestParam(required=false) String cursor,
            @RequestParam(required=false) String types,@RequestParam(defaultValue="false") boolean includeRelated,
            @RequestParam(defaultValue="50") int size,
            @RequestParam(required=false) @DateTimeFormat(iso=DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam(required=false) @DateTimeFormat(iso=DateTimeFormat.ISO.DATE_TIME) LocalDateTime to) {
        return investigation.timeline(id,cursor,types,includeRelated,size,from,to);
    }
    @PostMapping("/incidents")
    @ResponseStatus(org.springframework.http.HttpStatus.CREATED)
    public SiemDtos.Incident create(@Valid @RequestBody SiemWorkspaceService.Create request,Authentication authentication) {
        return workspace.create(request,authentication);
    }
    @PostMapping("/incidents/{id}/response-checks")
    public SiemDtos.Incident verify(@PathVariable String id,@Valid @RequestBody SiemContainmentService.Verification request,Authentication authentication) {
        containment.verify(id,request,authentication);return workflow.getIncident(id).incident();
    }
    @GetMapping("/incidents/{id}/containment-actions")
    public List<SiemContainmentService.Action> actions(@PathVariable String id) {return containment.list(id);}
    @PostMapping("/incidents/{id}/containment-actions")
    public SiemContainmentService.Action isolate(@PathVariable String id,@Valid @RequestBody SiemContainmentService.Request request,Authentication authentication) {
        return containment.isolate(id,request,authentication);
    }
    @PostMapping("/containment-actions/{id}/release")
    public SiemContainmentService.Action release(@PathVariable String id,@Valid @RequestBody SiemContainmentService.Release request,Authentication authentication) {
        return containment.release(id,request,authentication);
    }
}
