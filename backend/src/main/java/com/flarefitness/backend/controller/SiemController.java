package com.flarefitness.backend.controller;

import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.siem.IncidentClassification;
import com.flarefitness.backend.entity.siem.IncidentSeverity;
import com.flarefitness.backend.entity.siem.IncidentStatus;
import com.flarefitness.backend.entity.siem.IncidentQueueTier;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.service.siem.SiemElasticGateway;
import com.flarefitness.backend.service.siem.SiemIncidentService;
import com.flarefitness.backend.service.siem.SiemStatusService;
import com.flarefitness.backend.service.siem.SiemResponseActionService;
import com.flarefitness.backend.service.siem.SiemUebaModelService;
import com.flarefitness.backend.service.siem.SiemAccountWatchService;
import jakarta.validation.Valid;
import java.time.LocalDateTime;
import java.util.List;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/siem")
public class SiemController {
    private final SiemIncidentService incidentService;
    private final SiemStatusService statusService;
    private final SiemElasticGateway elasticGateway;
    private final SiemResponseActionService responseActionService;
    private final SiemUebaModelService uebaModelService;
    private final SiemAccountWatchService accountWatchService;

    public SiemController(
            SiemIncidentService incidentService,
            SiemStatusService statusService,
            SiemElasticGateway elasticGateway,
            SiemResponseActionService responseActionService,
            SiemUebaModelService uebaModelService,
            SiemAccountWatchService accountWatchService
    ) {
        this.incidentService = incidentService;
        this.statusService = statusService;
        this.elasticGateway = elasticGateway;
        this.responseActionService = responseActionService;
        this.uebaModelService = uebaModelService;
        this.accountWatchService = accountWatchService;
    }

    @GetMapping("/capabilities")
    public SiemDtos.Capabilities capabilities(Authentication authentication) {
        return incidentService.capabilities(authentication);
    }

    @GetMapping("/ueba/status")
    public SiemDtos.UebaStatus uebaStatus() {
        return uebaModelService.status();
    }

    @GetMapping("/accounts/watchlist")
    public PageResponse<SiemDtos.WatchAccount> watchAccounts(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(defaultValue = "RISK") SiemDtos.AccountWatchView view) {
        return accountWatchService.watchlist(from, to, page, size, view);
    }

    @GetMapping("/accounts/{id}/behavior")
    public PageResponse<SiemDtos.BehaviorWindow> accountBehavior(
            @PathVariable String id,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return accountWatchService.behavior(id, from, to, page, size);
    }

    @GetMapping("/incidents/{id}/behavior-windows")
    public PageResponse<SiemDtos.BehaviorWindow> incidentBehaviorWindows(
            @PathVariable String id,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return accountWatchService.incidentWindows(id, page, size);
    }

    @GetMapping("/incidents/{id}/security-events")
    public PageResponse<SiemDtos.SecurityEventEvidence> incidentSecurityEvents(
            @PathVariable String id,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "200") int size) {
        return accountWatchService.incidentEvents(id, page, size);
    }

    @PostMapping("/ueba/training-jobs")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public SiemDtos.UebaTrainingJob startUebaTraining(
            @Valid @RequestBody SiemDtos.StartUebaTraining request, Authentication authentication) {
        return uebaModelService.startTraining(request, authentication);
    }

    @GetMapping("/ueba/recipes")
    public List<SiemDtos.UebaRecipe> uebaRecipes(Authentication authentication) {
        return uebaModelService.recipes(authentication);
    }

    @PostMapping("/ueba/models/{version}/evaluate")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public SiemDtos.UebaTrainingJob evaluateUebaModel(@PathVariable String version,
            @Valid @RequestBody SiemDtos.EvaluateUebaModel request, Authentication authentication) {
        return uebaModelService.evaluate(version, request, authentication);
    }

    @GetMapping("/ueba/training-jobs")
    public PageResponse<SiemDtos.UebaTrainingJob> uebaTrainingJobs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            Authentication authentication) {
        return uebaModelService.listTrainingJobs(page, size, authentication);
    }

    @GetMapping("/ueba/training-jobs/{jobId}")
    public SiemDtos.UebaTrainingJob uebaTrainingJob(@PathVariable String jobId, Authentication authentication) {
        return uebaModelService.refreshTrainingJob(jobId, authentication);
    }

    @PostMapping("/ueba/models/{version}/activate")
    public SiemDtos.UebaTrainingJob activateUebaModel(@PathVariable String version,
                                                       Authentication authentication) {
        return uebaModelService.activate(version, authentication);
    }

    @GetMapping("/overview")
    public SiemDtos.Overview overview() {
        SiemDtos.Status status = statusService.status();
        return incidentService.overview(status.elasticsearchAvailable(), status.lastSuccessAt());
    }

    @GetMapping("/dashboard-summary")
    public SiemDtos.DashboardSummary dashboardSummary(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to
    ) {
        return incidentService.dashboardSummary(from, to);
    }

    @GetMapping("/incidents")
    public PageResponse<SiemDtos.Incident> incidents(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(required = false) IncidentStatus status,
            @RequestParam(required = false) IncidentSeverity severity,
            @RequestParam(required = false) IncidentClassification classification,
            @RequestParam(required = false) SiemDtos.IncidentScope scope,
            @RequestParam(required = false) SiemDtos.IncidentSort sort,
            @RequestParam(required = false) IncidentQueueTier queueTier,
            @RequestParam(required = false) IncidentOrigin origin,
            @RequestParam(required = false) String targetUserId,
            @RequestParam(required = false) String assigneeUserId,
            @RequestParam(defaultValue = "false") boolean mine,
            @RequestParam(defaultValue = "false") boolean includeAssignedAnalyst,
            @RequestParam(required = false, name = "q") String query,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            Authentication authentication
    ) {
        var found = incidentService.findIncidents(
                page, size, status, severity, classification, scope, sort, query, from, to,
                queueTier, origin, targetUserId, assigneeUserId, mine, authentication);
        return includeAssignedAnalyst ? incidentService.includeAssignedAnalysts(found) : found;
    }

    @GetMapping("/incidents/{id}")
    public SiemDtos.IncidentDetail incident(@PathVariable String id,
            @RequestParam(defaultValue = "false") boolean includeAssignedAnalyst) {
        var detail = incidentService.getIncident(id);
        return includeAssignedAnalyst ? incidentService.includeAssignedAnalyst(detail) : detail;
    }

    @GetMapping("/incidents/{id}/alerts")
    public List<SiemDtos.AlertRef> incidentAlerts(@PathVariable String id) {
        return incidentService.getAlerts(id);
    }

    @GetMapping("/incidents/{id}/logs")
    public List<SiemDtos.ElasticDocument> incidentLogs(@PathVariable String id) {
        SiemDtos.Incident value = incidentService.getIncident(id).incident();
        return elasticGateway.searchIncidentLogs(
                value.sourceIp(), value.firstSeen().minusMinutes(5), value.lastSeen().plusMinutes(5), 100);
    }

    @GetMapping("/incidents/{id}/security-logs")
    public List<SiemDtos.ElasticDocument> incidentSecurityLogs(@PathVariable String id) {
        SiemDtos.Incident value = incidentService.getIncident(id).incident();
        if (value.origin() != IncidentOrigin.UEBA || value.targetUserId() == null) {
            throw new com.flarefitness.backend.exception.BadRequestException(
                    "Security documents are available only for UEBA incidents.");
        }
        return elasticGateway.searchIncidentSecurityDocuments(value.targetUserId(), value.sourceIp(),
                value.firstSeen().minusMinutes(5), value.lastSeen().plusMinutes(5), 100);
    }

    @GetMapping("/incidents/{id}/prevention-logs")
    public List<SiemDtos.ElasticDocument> incidentPreventionLogs(@PathVariable String id) {
        SiemDtos.Incident value = incidentService.getIncident(id).incident();
        if (value.origin() != IncidentOrigin.PREVENTION) {
            throw new com.flarefitness.backend.exception.BadRequestException(
                    "Gateway evidence is available only for prevention incidents.");
        }
        return elasticGateway.searchIncidentPreventionDocuments(value.sourceIp(),
                value.firstSeen().minusMinutes(5), value.lastSeen().plusMinutes(5), 100);
    }

    @PatchMapping("/incidents/{id}")
    public SiemDtos.Incident updateIncident(
            @PathVariable String id,
            @Valid @RequestBody SiemDtos.UpdateIncident request,
            Authentication authentication
    ) {
        return incidentService.updateIncident(id, request, authentication);
    }

    @PostMapping("/incidents/{id}/transitions")
    public SiemDtos.Incident transitionIncident(
            @PathVariable String id,
            @Valid @RequestBody SiemDtos.TransitionIncident request,
            Authentication authentication
    ) {
        return incidentService.transitionIncident(id, request, authentication);
    }

    @PostMapping("/incidents/{id}/response-actions")
    public SiemDtos.SessionRevocationResult revokeCustomerSessions(
            @PathVariable String id,
            @Valid @RequestBody SiemDtos.RevokeSessions request,
            Authentication authentication
    ) {
        return responseActionService.revokeCustomerSessions(id, request, authentication);
    }

    @PostMapping("/incidents/{id}/notes")
    @ResponseStatus(HttpStatus.CREATED)
    public SiemDtos.Note addNote(
            @PathVariable String id,
            @Valid @RequestBody SiemDtos.AddNote request,
            Authentication authentication
    ) {
        return incidentService.addNote(id, request, authentication);
    }

    @GetMapping("/incidents/{id}/history")
    public List<SiemDtos.History> incidentHistory(@PathVariable String id) {
        return incidentService.incidentHistory(id);
    }

    @GetMapping("/history")
    public PageResponse<SiemDtos.History> history(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        return incidentService.history(page, size);
    }

    @GetMapping("/logs")
    public List<SiemDtos.ElasticDocument> logs(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(defaultValue = "50") int size
    ) {
        return elasticGateway.searchLogs(from, to, size);
    }

    @GetMapping("/geo")
    public List<SiemDtos.GeoBucket> geo(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to
    ) {
        return elasticGateway.geo(from, to);
    }

    @GetMapping("/status")
    public SiemDtos.Status status() {
        return statusService.status();
    }

    @GetMapping("/test-windows")
    public List<SiemDtos.TestWindow> testWindows() {
        return incidentService.testWindows();
    }

    @PostMapping("/test-windows")
    @ResponseStatus(HttpStatus.CREATED)
    public SiemDtos.TestWindow createTestWindow(
            @Valid @RequestBody SiemDtos.TestWindowRequest request,
            Authentication authentication
    ) {
        return incidentService.createTestWindow(request, authentication);
    }

    @PatchMapping("/test-windows/{id}/end")
    public SiemDtos.TestWindow endTestWindow(@PathVariable String id, @RequestParam long version,
                                            Authentication authentication) {
        return incidentService.endTestWindow(id, version, authentication);
    }
}
