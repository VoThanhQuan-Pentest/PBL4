package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.entity.siem.SiemIncident;
import com.flarefitness.backend.entity.siem.SiemSecurityEvent;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.repository.siem.SiemSecurityEventRepository;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SiemAccountWatchService {
    private final SiemAccountBehaviorWindowRepository windows;
    private final SiemIncidentRepository incidents;
    private final SiemSecurityEventRepository events;

    public SiemAccountWatchService(SiemAccountBehaviorWindowRepository windows,
                                   SiemIncidentRepository incidents,
                                   SiemSecurityEventRepository events) {
        this.windows = windows;
        this.incidents = incidents;
        this.events = events;
    }

    @Transactional(readOnly = true)
    public PageResponse<SiemDtos.WatchAccount> watchlist(LocalDateTime from, LocalDateTime to,
                                                          int page, int size) {
        return watchlist(from, to, page, size, SiemDtos.AccountWatchView.RISK);
    }

    @Transactional(readOnly = true)
    public PageResponse<SiemDtos.WatchAccount> watchlist(LocalDateTime from, LocalDateTime to,
                                                          int page, int size, SiemDtos.AccountWatchView view) {
        validate(from, to, page, size);
        if (view == null) throw new BadRequestException("Invalid account watch view.");
        LocalDateTime historyFrom = to.minusDays(AccountBaselinePolicy.HISTORY_DAYS);
        LocalDateTime joinFrom = from.isBefore(historyFrom) ? from : historyFrom;
        Page<SiemDtos.WatchAccount> result = windows.findAccountSummaries(from, to, historyFrom,
                joinFrom, view.name(), PageRequest.of(page, size)).map(row -> new SiemDtos.WatchAccount(
                        row.getAccountId(), row.getMaximumRisk() == null ? 0 : row.getMaximumRisk(),
                        row.getLastWindow(), row.getFlaggedWindows(),
                        AccountBaselinePolicy.status(row.getHistoryWindows(), row.getTrustedWindows()),
                        row.getTrustedWindows(), AccountBaselinePolicy.REQUIRED_WINDOWS,
                        AccountBaselinePolicy.HISTORY_DAYS, to, row.getMaximumRisk() != null));
        return PageResponse.from(result);
    }

    @Transactional(readOnly = true)
    public PageResponse<SiemDtos.BehaviorWindow> behavior(String accountId, LocalDateTime from,
                                                           LocalDateTime to, int page, int size) {
        validate(from, to, page, size);
        if (accountId == null || accountId.isBlank() || accountId.length() > 64) {
            throw new BadRequestException("Invalid account ID.");
        }
        Page<SiemDtos.BehaviorWindow> result = windows
                .findByAccountIdAndWindowStartGreaterThanEqualAndWindowStartLessThanOrderByWindowStartDesc(
                        accountId, from, to, PageRequest.of(page, size))
                .map(this::toDto);
        return PageResponse.from(result);
    }

    @Transactional(readOnly = true)
    public PageResponse<SiemDtos.BehaviorWindow> incidentWindows(String incidentId, int page, int size) {
        IncidentWindow scope = incidentWindow(incidentId);
        validatePage(page, size, 20);
        return PageResponse.from(windows
                .findByAccountIdAndWindowStartGreaterThanEqualAndWindowStartLessThanOrderByWindowStartDesc(
                        scope.accountId(), scope.from(), scope.to(), PageRequest.of(page, size))
                .map(this::toDto));
    }

    @Transactional(readOnly = true)
    public PageResponse<SiemDtos.SecurityEventEvidence> incidentEvents(String incidentId,
                                                                        int page, int size) {
        IncidentWindow scope = incidentWindow(incidentId);
        validatePage(page, size, 200);
        return PageResponse.from(events.findAccountEvidence(scope.accountId(), scope.from(),
                scope.to(), PageRequest.of(page, size)).map(this::toEvidence));
    }

    private IncidentWindow incidentWindow(String incidentId) {
        SiemIncident incident = incidents.findById(incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("Incident not found."));
        if (incident.getOrigin() != IncidentOrigin.UEBA || incident.getTargetUserId() == null) {
            throw new BadRequestException("Account behavior evidence is available only for UEBA incidents.");
        }
        LocalDateTime from = incident.getBucketStart().truncatedTo(ChronoUnit.HOURS);
        return new IncidentWindow(incident.getTargetUserId(), from, from.plusHours(1));
    }

    private SiemDtos.SecurityEventEvidence toEvidence(SiemSecurityEvent event) {
        return new SiemDtos.SecurityEventEvidence(event.getId(), event.getEventTimestamp(),
                event.getEventType(), event.getAction(), event.getOutcome(), event.getSourceIp(),
                event.getRouteGroup(), event.getHttpStatus(), event.getUserAgentFamily(),
                event.getTraceId(), event.getDemoLabel());
    }

    private SiemDtos.BehaviorWindow toDto(SiemAccountBehaviorWindow window) {
        Map<String, Double> features = new LinkedHashMap<>();
        int schema = window.hasModelFeatures(2) ? 2 : 1;
        List<Double> values = window.modelFeatureVector(schema);
        List<String> names = AccountBehaviorFeatures.names(schema);
        for (int index = 0; index < names.size(); index++) {
            features.put(names.get(index), values.get(index));
        }
        return new SiemDtos.BehaviorWindow(window.getId(), window.getAccountId(),
                window.getWindowStart(), window.getWindowEnd(), window.getEventCount(),
                window.isBaselineEstablished(), features, window.getSourceIp(),
                window.getUserAgentFamily(), window.getDemoLabel(), window.getScoreStatus().name(),
                window.getModelVersion(), window.getAnomalyPercentile(),
                window.getRiskScore(), window.getRiskReasons(), window.getPersonalFeatureSchemaVersion(),
                window.getScoredFeatureSchemaVersion());
    }

    private void validate(LocalDateTime from, LocalDateTime to, int page, int size) {
        if (from == null || to == null || !from.isBefore(to)
                || Duration.between(from, to).compareTo(Duration.ofDays(30)) > 0
                || page < 0 || size < 1 || size > 100) {
            throw new BadRequestException("Invalid watchlist range or page size.");
        }
    }

    private void validatePage(int page, int size, int maximum) {
        if (page < 0 || size < 1 || size > maximum) {
            throw new BadRequestException("Invalid incident evidence page size.");
        }
    }

    private record IncidentWindow(String accountId, LocalDateTime from, LocalDateTime to) { }
}
