package com.flarefitness.backend.service.siem;

import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.siem.IncidentClassification;
import com.flarefitness.backend.entity.siem.IncidentConclusion;
import com.flarefitness.backend.entity.siem.IncidentSeverity;
import com.flarefitness.backend.entity.siem.IncidentStatus;
import com.flarefitness.backend.entity.siem.IncidentQueueTier;
import com.flarefitness.backend.entity.siem.IncidentOrigin;
import com.flarefitness.backend.entity.siem.SiemAlertRef;
import com.flarefitness.backend.entity.siem.SiemIncident;
import com.flarefitness.backend.entity.siem.SiemIncidentHistory;
import com.flarefitness.backend.entity.siem.SiemIncidentNote;
import com.flarefitness.backend.entity.siem.SiemTestWindow;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ConflictException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.repository.siem.SiemAlertRefRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentHistoryRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentNoteRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.repository.siem.SiemTestWindowRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import jakarta.persistence.criteria.Predicate;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.HashMap;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.Authentication;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SiemIncidentService {
    private final SiemIncidentRepository incidentRepository;
    private final SiemAlertRefRepository alertRefRepository;
    private final SiemIncidentNoteRepository noteRepository;
    private final SiemIncidentHistoryRepository historyRepository;
    private final SiemTestWindowRepository testWindowRepository;
    private final UserRepository userRepository;

    public SiemIncidentService(
            SiemIncidentRepository incidentRepository,
            SiemAlertRefRepository alertRefRepository,
            SiemIncidentNoteRepository noteRepository,
            SiemIncidentHistoryRepository historyRepository,
            SiemTestWindowRepository testWindowRepository,
            UserRepository userRepository
    ) {
        this.incidentRepository = incidentRepository;
        this.alertRefRepository = alertRefRepository;
        this.noteRepository = noteRepository;
        this.historyRepository = historyRepository;
        this.testWindowRepository = testWindowRepository;
        this.userRepository = userRepository;
    }

    public SiemDtos.Capabilities capabilities(Authentication authentication) {
        String role = actorAuthority(authentication);
        boolean higherTier = isHigherTier(role);
        return new SiemDtos.Capabilities(role,
                higherTier
                        ? List.of(SiemDtos.TransitionAction.values())
                        : List.of(SiemDtos.TransitionAction.CLAIM, SiemDtos.TransitionAction.ESCALATE,
                                SiemDtos.TransitionAction.CLOSE, SiemDtos.TransitionAction.REOPEN),
                higherTier, "ROLE_ADMIN".equals(role));
    }

    @Transactional(readOnly = true)
    public SiemDtos.Overview overview(boolean elasticsearchAvailable, LocalDateTime lastSuccess) {
        EnumMap<IncidentSeverity, Long> bySeverity = new EnumMap<>(IncidentSeverity.class);
        for (IncidentSeverity severity : IncidentSeverity.values()) {
            bySeverity.put(severity, incidentRepository.countBySeverity(severity));
        }
        EnumMap<IncidentClassification, Long> byClassification = new EnumMap<>(IncidentClassification.class);
        for (IncidentClassification classification : IncidentClassification.values()) {
            byClassification.put(classification, incidentRepository.countByClassification(classification));
        }
        long newCount = incidentRepository.countByStatus(IncidentStatus.NEW);
        long inProgress = incidentRepository.countByStatus(IncidentStatus.IN_PROGRESS);
        return new SiemDtos.Overview(
                newCount + inProgress,
                newCount,
                inProgress,
                incidentRepository.countByLastSeenGreaterThanEqual(LocalDateTime.now(ZoneOffset.UTC).minusHours(24)),
                bySeverity,
                byClassification,
                lastSuccess,
                elasticsearchAvailable);
    }

    @Transactional(readOnly = true)
    public SiemDtos.DashboardSummary dashboardSummary(LocalDateTime from, LocalDateTime to) {
        validateRange(from, to);
        if (from == null || to == null) {
            throw new BadRequestException("Can cung cap dong thoi from va to.");
        }
        Specification<SiemIncident> timeRange = timeRange(from, to);
        EnumMap<IncidentSeverity, Long> bySeverity = new EnumMap<>(IncidentSeverity.class);
        for (IncidentSeverity severity : IncidentSeverity.values()) {
            bySeverity.put(severity, incidentRepository.count(timeRange.and(equal("severity", severity))));
        }
        EnumMap<IncidentStatus, Long> byStatus = new EnumMap<>(IncidentStatus.class);
        for (IncidentStatus status : IncidentStatus.values()) {
            byStatus.put(status, incidentRepository.count(timeRange.and(equal("status", status))));
        }
        EnumMap<IncidentClassification, Long> byClassification = new EnumMap<>(IncidentClassification.class);
        for (IncidentClassification classification : IncidentClassification.values()) {
            byClassification.put(
                    classification,
                    incidentRepository.count(timeRange.and(equal("classification", classification))));
        }
        EnumMap<IncidentQueueTier, Long> byQueueTier = new EnumMap<>(IncidentQueueTier.class);
        for (IncidentQueueTier tier : IncidentQueueTier.values()) {
            byQueueTier.put(tier, incidentRepository.count(timeRange.and(equal("queueTier", tier))));
        }
        EnumMap<IncidentOrigin, Long> byOrigin = new EnumMap<>(IncidentOrigin.class);
        for (IncidentOrigin origin : IncidentOrigin.values()) {
            byOrigin.put(origin, incidentRepository.count(timeRange.and(equal("origin", origin))));
        }
        long knownOrigins=byOrigin.values().stream().mapToLong(Long::longValue).sum();
        long allOrigins=incidentRepository.count(timeRange);
        if(allOrigins>knownOrigins)byOrigin.merge(IncidentOrigin.UNKNOWN,allOrigins-knownOrigins,Long::sum);
        return new SiemDtos.DashboardSummary(
                from,
                to,
                incidentRepository.count(timeRange),
                byClassification.getOrDefault(IncidentClassification.INVESTIGATE, 0L),
                byClassification.getOrDefault(IncidentClassification.POTENTIAL_NOISE, 0L),
                byStatus.getOrDefault(IncidentStatus.CLOSED, 0L),
                bySeverity,
                byStatus,
                byClassification,
                byQueueTier,
                byOrigin);
    }

    @Transactional(readOnly = true)
    public PageResponse<SiemDtos.Incident> findIncidents(
            int page,
            int size,
            IncidentStatus status,
            IncidentSeverity severity,
            IncidentClassification classification,
            SiemDtos.IncidentScope scope,
            SiemDtos.IncidentSort sort,
            String query,
            LocalDateTime from,
            LocalDateTime to
    ) {
        return findIncidents(page, size, status, severity, classification, scope, sort,
                query, from, to, null, null, null, null, false, null);
    }

    @Transactional(readOnly = true)
    public PageResponse<SiemDtos.Incident> findIncidents(
            int page, int size, IncidentStatus status, IncidentSeverity severity,
            IncidentClassification classification, SiemDtos.IncidentScope scope,
            SiemDtos.IncidentSort sort, String query, LocalDateTime from, LocalDateTime to,
            IncidentQueueTier queueTier, IncidentOrigin origin, String targetUserId,
            String assigneeUserId, boolean mine, Authentication authentication
    ) {
        int validPage = validPage(page);
        int validSize = validSize(size);
        validateRange(from, to);
        String role = authentication == null ? null : actorAuthority(authentication);
        IncidentQueueTier effectiveTier = queueTier != null ? queueTier
                : "ROLE_SOC_L1".equals(role) ? IncidentQueueTier.L1
                : "ROLE_SOC_L2".equals(role) ? IncidentQueueTier.L2 : null;
        String actorFilter = mine ? actorId(authentication) : null;
        String targetFilter = validatedUserId(targetUserId);
        String assigneeFilter = validatedUserId(assigneeUserId);
        boolean legacyRequest = scope == null;
        SiemDtos.IncidentScope effectiveScope = scope == null ? SiemDtos.IncidentScope.ALL : scope;
        SiemDtos.IncidentSort effectiveSort = sort == null ? SiemDtos.IncidentSort.LATEST : sort;
        LocalDateTime effectiveTo = to;
        LocalDateTime effectiveFrom = from;
        if (legacyRequest && from == null) {
            effectiveTo = LocalDateTime.now(ZoneOffset.UTC);
            effectiveFrom = effectiveTo.minusHours(24);
        }
        LocalDateTime finalFrom = effectiveFrom;
        LocalDateTime finalTo = effectiveTo;
        Specification<SiemIncident> spec = (root, criteriaQuery, builder) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (effectiveTier != null) predicates.add(builder.equal(root.get("queueTier"), effectiveTier));
            if (origin != null) predicates.add(origin==IncidentOrigin.UNKNOWN?builder.or(builder.isNull(root.get("origin")),builder.equal(root.get("origin"),origin)):builder.equal(root.get("origin"),origin));
            if (targetFilter != null) predicates.add(builder.equal(root.get("targetUserId"), targetFilter));
            if (assigneeFilter != null) predicates.add(builder.equal(root.get("assigneeUserId"), assigneeFilter));
            if (actorFilter != null) predicates.add(builder.equal(root.get("assigneeUserId"), actorFilter));
            if (effectiveScope == SiemDtos.IncidentScope.OPEN) {
                predicates.add(root.get("status").in(IncidentStatus.NEW, IncidentStatus.IN_PROGRESS));
            }
            if (status != null) predicates.add(builder.equal(root.get("status"), status));
            if (severity != null) predicates.add(builder.equal(root.get("severity"), severity));
            if (classification != null) predicates.add(builder.equal(root.get("classification"), classification));
            if (finalFrom != null) predicates.add(builder.greaterThanOrEqualTo(root.get("lastSeen"), finalFrom));
            if (finalTo != null) predicates.add(builder.lessThanOrEqualTo(root.get("lastSeen"), finalTo));
            if (query != null && !query.isBlank()) {
                String term = "%" + query.trim().toLowerCase(Locale.ROOT) + "%";
                predicates.add(builder.or(
                        builder.like(builder.lower(root.get("title")), term),
                        builder.like(builder.lower(root.get("sourceIp")), term),
                        builder.like(builder.lower(root.get("ruleId")), term)));
            }
            if (!Long.class.equals(criteriaQuery.getResultType()) && !long.class.equals(criteriaQuery.getResultType())) {
                if (effectiveSort == SiemDtos.IncidentSort.PRIORITY) {
                    criteriaQuery.orderBy(
                            builder.asc(builder.selectCase(root.get("classification"))
                                    .when(IncidentClassification.INVESTIGATE, 0).otherwise(1)),
                            builder.asc(builder.selectCase(root.get("severity")).when(IncidentSeverity.URGENT,0).when(IncidentSeverity.HIGH,1).when(IncidentSeverity.MEDIUM,2).otherwise(3)),
                            builder.asc(root.get("firstSeen")),
                            builder.asc(builder.selectCase(root.get("status"))
                                    .when(IncidentStatus.NEW, 0)
                                    .when(IncidentStatus.IN_PROGRESS, 1)
                                    .otherwise(2)),
                            builder.desc(root.get("lastSeen")),
                            builder.asc(root.get("id")));
                } else {
                    criteriaQuery.orderBy(builder.desc(root.get("lastSeen")), builder.asc(root.get("id")));
                }
            }
            return builder.and(predicates.toArray(Predicate[]::new));
        };
        Page<SiemDtos.Incident> result = incidentRepository.findAll(spec, PageRequest.of(validPage, validSize))
                .map(this::toIncident);
        return PageResponse.from(result);
    }

    private Specification<SiemIncident> timeRange(LocalDateTime from, LocalDateTime to) {
        return (root, ignored, builder) -> builder.and(
                builder.greaterThanOrEqualTo(root.get("lastSeen"), from),
                builder.lessThanOrEqualTo(root.get("lastSeen"), to));
    }

    private <T> Specification<SiemIncident> equal(String field, T value) {
        return (root, ignored, builder) -> builder.equal(root.get(field), value);
    }

    @Transactional(readOnly=true)
    public SiemDtos.Incident incidentProjection(String id) {return toIncident(requireIncident(id));}

    @Transactional(readOnly = true)
    public SiemDtos.IncidentDetail getIncident(String id) {
        SiemIncident incident = requireIncident(id);
        List<SiemDtos.Note> notes = noteRepository.findTop100ByIncidentIdOrderByCreatedAtDesc(id)
                .stream().map(this::toNote).toList();
        return new SiemDtos.IncidentDetail(toIncident(incident), notes);
    }

    @Transactional(readOnly = true)
    public List<SiemDtos.AlertRef> getAlerts(String id) {
        requireIncident(id);
        return alertRefRepository.findTop100ByIncidentIdOrderByEventTimestampDesc(id)
                .stream().map(this::toAlertRef).toList();
    }

    @Transactional
    public SiemDtos.Incident transitionIncident(
            String id, SiemDtos.TransitionIncident request, Authentication authentication) {
        SiemIncident incident = requireIncident(id);
        if (!incident.getVersion().equals(request.expectedVersion())) {
            throw new ConflictException("Incident da thay doi. Hay tai lai truoc khi cap nhat.");
        }
        String actorId = actorId(authentication);
        String authority = actorAuthority(authentication);
        IncidentQueueTier tier = incident.getQueueTier();
        if (tier == IncidentQueueTier.L2 && !isHigherTier(authority)) {
            throw new AccessDeniedException("Hang doi L2 chi danh cho SOC L2.");
        }
        String previous = incident.getQueueTier() + "/" + incident.getStatus() + "/" + incident.getConclusion();
        String reason = trimToNull(request.reason());

        switch (request.action()) {
            case CLAIM -> {
                if (incident.getStatus() != IncidentStatus.NEW || incident.getAssigneeUserId() != null) {
                    throw new ConflictException("Incident khong con trong hang doi cho nhan.");
                }
                incident.setStatus(IncidentStatus.IN_PROGRESS);
                incident.setAssigneeUserId(actorId);
            }
            case ESCALATE -> {
                if (tier != IncidentQueueTier.L1 || incident.getStatus() != IncidentStatus.IN_PROGRESS) {
                    throw new ConflictException("Chi incident dang xu ly o L1 moi duoc chuyen len L2.");
                }
                requireAssignedToActor(incident, actorId);
                requireTransitionReason(reason);
                incident.setQueueTier(IncidentQueueTier.L2);
                incident.setStatus(IncidentStatus.NEW);
                incident.setAssigneeUserId(null);
            }
            case RETURN_TO_L1 -> {
                if (!isHigherTier(authority)) {
                    throw new AccessDeniedException("Chi SOC L2 duoc tra incident ve L1.");
                }
                if (tier != IncidentQueueTier.L2 || incident.getStatus() != IncidentStatus.IN_PROGRESS) {
                    throw new ConflictException("Chi incident dang xu ly o L2 moi duoc tra ve L1.");
                }
                requireAssignedToActor(incident, actorId);
                requireTransitionReason(reason);
                incident.setQueueTier(IncidentQueueTier.L1);
                incident.setStatus(IncidentStatus.NEW);
                incident.setAssigneeUserId(null);
            }
            case CLOSE -> {
                if (incident.getStatus() != IncidentStatus.IN_PROGRESS) {
                    throw new ConflictException("Can nhan incident truoc khi dong.");
                }
                requireAssignedToActor(incident, actorId);
                requireTransitionReason(reason);
                requireClosePermission(incident, authority, request.conclusion());
                incident.setStatus(IncidentStatus.CLOSED);
                incident.setConclusion(request.conclusion());
            }
            case REOPEN -> {
                if (incident.getStatus() != IncidentStatus.CLOSED) {
                    throw new ConflictException("Chi incident da dong moi duoc mo lai.");
                }
                requireTransitionReason(reason);
                incident.setStatus(IncidentStatus.NEW);
                incident.setAssigneeUserId(null);
                incident.setConclusion(IncidentConclusion.UNREVIEWED);
            }
        }

        incident.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC));
        SiemIncident saved = incidentRepository.saveAndFlush(incident);
        if (reason != null) saveNote(saved.getId(), actorId, reason);
        saveHistory(saved.getId(), actorId, request.action().name(), previous,
                saved.getQueueTier() + "/" + saved.getStatus() + "/" + saved.getConclusion(), reason);
        return toIncident(saved);
    }

    private void requireClosePermission(SiemIncident incident, String authority,
                                        IncidentConclusion conclusion) {
        if (conclusion == null || conclusion == IncidentConclusion.UNREVIEWED) {
            throw new BadRequestException("Can chon ket luan truoc khi dong incident.");
        }
        if (!isHigherTier(authority) && (conclusion == IncidentConclusion.TRUE_POSITIVE
                || Boolean.TRUE.equals(incident.getMissingData())
                || incident.getSeverity() == IncidentSeverity.HIGH
                || incident.getSeverity() == IncidentSeverity.URGENT)) {
            throw new AccessDeniedException("Incident nay can SOC L2 ket luan.");
        }
        if (conclusion==IncidentConclusion.TRUE_POSITIVE && (incident.getResponseVerifiedAt()==null
                || incident.getRecoveryVerifiedAt()==null || !java.util.Objects.equals(incident.getVersion(),incident.getResponseVerificationVersion()))) {
            throw new ConflictException("Verify response and recovery against the current incident version before confirming closure.");
        }
    }

    private void requireTransitionReason(String reason) {
        if (reason == null) throw new BadRequestException("Can ghi ly do cho thao tac nay.");
    }

    private void requireAssignedToActor(SiemIncident incident, String actorId) {
        if (!actorId.equals(incident.getAssigneeUserId())) {
            throw new ConflictException("Incident dang duoc mot analyst khac xu ly.");
        }
    }

    @Transactional
    public SiemDtos.Incident updateIncident(String id, SiemDtos.UpdateIncident request, Authentication authentication) {
        SiemIncident incident = requireIncident(id);
        if (!incident.getVersion().equals(request.version())) {
            throw new ConflictException("Incident da thay doi. Hay tai lai truoc khi cap nhat.");
        }
        String actorId = actorId(authentication);
        String authority = actorAuthority(authentication);
        if (incident.getQueueTier() == IncidentQueueTier.L2 && !isHigherTier(authority)) {
            throw new AccessDeniedException("Hang doi L2 chi danh cho SOC L2.");
        }
        IncidentStatus previousStatus = incident.getStatus();
        IncidentConclusion previousConclusion = incident.getConclusion();

        if (request.status() == IncidentStatus.IN_PROGRESS) {
            if (incident.getAssigneeUserId() != null && !incident.getAssigneeUserId().equals(actorId)) {
                throw new ConflictException("Incident dang duoc mot analyst khac xu ly.");
            }
            if (previousStatus == IncidentStatus.CLOSED) {
                requireTransitionReason(trimToNull(request.note()));
                incident.setConclusion(IncidentConclusion.UNREVIEWED);
            }
            incident.setAssigneeUserId(actorId);
            incident.setStatus(IncidentStatus.IN_PROGRESS);
        } else if (request.status() == IncidentStatus.CLOSED) {
            if (incident.getAssigneeUserId() != null && !incident.getAssigneeUserId().equals(actorId)) {
                throw new ConflictException("Incident dang duoc mot analyst khac xu ly.");
            }
            if (request.conclusion() == null || request.conclusion() == IncidentConclusion.UNREVIEWED) {
                throw new BadRequestException("Can chon ket luan truoc khi dong incident.");
            }
            if (request.note() == null || request.note().isBlank()) {
                throw new BadRequestException("Can ghi chu ket luan truoc khi dong incident.");
            }
            if (previousStatus != IncidentStatus.IN_PROGRESS) {
                throw new ConflictException("Can nhan incident truoc khi dong.");
            }
            requireAssignedToActor(incident, actorId);
            requireClosePermission(incident, authority, request.conclusion());
            incident.setStatus(IncidentStatus.CLOSED);
            incident.setConclusion(request.conclusion());
            if (incident.getAssigneeUserId() == null) incident.setAssigneeUserId(actorId);
        } else if (request.status() == IncidentStatus.NEW) {
            throw new BadRequestException("NEW chi duoc tao tu luong canh bao; dung IN_PROGRESS de mo lai incident.");
        }

        if (request.manualInvestigateOverride() != null) {
            incident.setManualInvestigateOverride(request.manualInvestigateOverride());
            if (request.manualInvestigateOverride()) {
                incident.setClassification(IncidentClassification.INVESTIGATE);
            }
        }
        incident.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC));
        SiemIncident saved = incidentRepository.saveAndFlush(incident);
        if (request.note() != null && !request.note().isBlank()) {
            saveNote(saved.getId(), actorId, request.note());
        }
        saveHistory(saved.getId(), actorId, "INCIDENT_UPDATED",
                previousStatus + "/" + previousConclusion,
                saved.getStatus() + "/" + saved.getConclusion(), null);
        return toIncident(saved);
    }

    @Transactional
    public SiemDtos.Note addNote(String incidentId, SiemDtos.AddNote request, Authentication authentication) {
        requireIncident(incidentId);
        String actorId = actorId(authentication);
        SiemIncidentNote note = saveNote(incidentId, actorId, request.content());
        saveHistory(incidentId, actorId, "NOTE_ADDED", null, null, "Analyst note added");
        return toNote(note);
    }

    @Transactional(readOnly = true)
    public List<SiemDtos.History> incidentHistory(String incidentId) {
        requireIncident(incidentId);
        return historyRepository.findTop100ByIncidentIdOrderByCreatedAtDesc(incidentId)
                .stream().map(this::toHistory).toList();
    }

    @Transactional(readOnly = true)
    public PageResponse<SiemDtos.History> history(int page, int size) {
        Page<SiemDtos.History> result = historyRepository.findAllByOrderByCreatedAtDesc(
                PageRequest.of(validPage(page), validSize(size))).map(this::toHistory);
        return PageResponse.from(result);
    }

    @Transactional(readOnly = true)
    public List<SiemDtos.TestWindow> testWindows() {
        return testWindowRepository.findTop100ByOrderByStartsAtDesc().stream().map(this::toTestWindow).toList();
    }

    @Transactional
    public SiemDtos.TestWindow createTestWindow(SiemDtos.TestWindowRequest request, Authentication authentication) {
        requireTestWindowAdmin(authentication);
        if (!request.endsAt().isAfter(request.startsAt())) {
            throw new BadRequestException("Thoi gian ket thuc phai sau thoi gian bat dau.");
        }
        if (Duration.between(request.startsAt(), request.endsAt()).toDays() > 7) {
            throw new BadRequestException("Test window khong duoc dai hon 7 ngay.");
        }
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        SiemTestWindow window = new SiemTestWindow();
        window.setId("siem-window-" + UUID.randomUUID());
        window.setName(request.name().trim());
        window.setSourceIp(trimToNull(request.sourceIp()));
        window.setServiceId(trimToNull(request.serviceId()));
        window.setStartsAt(request.startsAt());
        window.setEndsAt(request.endsAt());
        window.setActive(true);
        window.setCreatedByUserId(actorId(authentication));
        window.setCreatedAt(now);
        window.setUpdatedAt(now);
        return toTestWindow(testWindowRepository.save(window));
    }

    @Transactional
    public SiemDtos.TestWindow endTestWindow(String id, long version, Authentication authentication) {
        requireTestWindowAdmin(authentication);
        SiemTestWindow window = testWindowRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay test window."));
        if (!window.getVersion().equals(version)) {
            throw new ConflictException("Test window da thay doi. Hay tai lai.");
        }
        window.setActive(false);
        window.setEndsAt(LocalDateTime.now(ZoneOffset.UTC));
        window.setUpdatedAt(LocalDateTime.now(ZoneOffset.UTC));
        return toTestWindow(testWindowRepository.saveAndFlush(window));
    }

    private void requireTestWindowAdmin(Authentication authentication) {
        if (!"ROLE_ADMIN".equals(actorAuthority(authentication))) {
            throw new AccessDeniedException("Chi quan tri vien duoc thay doi test window.");
        }
    }

    private SiemIncident requireIncident(String id) {
        return incidentRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay incident."));
    }

    private SiemIncidentNote saveNote(String incidentId, String actorId, String content) {
        SiemIncidentNote note = new SiemIncidentNote();
        note.setId("siem-note-" + UUID.randomUUID());
        note.setIncidentId(incidentId);
        note.setAuthorUserId(actorId);
        note.setContent(content.trim());
        note.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        return noteRepository.save(note);
    }

    private void saveHistory(String incidentId, String actorId, String action,
                             String previousValue, String newValue, String detail) {
        SiemIncidentHistory history = new SiemIncidentHistory();
        history.setId("siem-history-" + UUID.randomUUID());
        history.setIncidentId(incidentId);
        history.setActorUserId(actorId);
        history.setAction(action);
        history.setPreviousValue(previousValue);
        history.setNewValue(newValue);
        history.setDetail(detail);
        history.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        historyRepository.save(history);
    }

    private String actorId(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof CurrentUserPrincipal principal)) {
            throw new BadRequestException("Phien dang nhap khong hop le.");
        }
        return principal.getUser().getId();
    }

    private String actorAuthority(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof CurrentUserPrincipal principal)) {
            throw new AccessDeniedException("Phien SOC khong hop le.");
        }
        String authority = CurrentUserPrincipal.toAuthority(principal.getUser().getRole());
        if (!"ROLE_ADMIN".equals(authority) && !"ROLE_SOC_L1".equals(authority)
                && !"ROLE_SOC_L2".equals(authority)) {
            throw new AccessDeniedException("Tai khoan khong co quyen SOC.");
        }
        return authority;
    }

    private boolean isHigherTier(String authority) {
        return "ROLE_ADMIN".equals(authority) || "ROLE_SOC_L2".equals(authority);
    }

    private int validPage(int page) {
        if (page < 0) throw new BadRequestException("page phai lon hon hoac bang 0.");
        return page;
    }

    private int validSize(int size) {
        if (size < 1 || size > 100) throw new BadRequestException("size phai tu 1 den 100.");
        return size;
    }

    private void validateRange(LocalDateTime from, LocalDateTime to) {
        if ((from == null) != (to == null)) {
            throw new BadRequestException("Can cung cap dong thoi from va to.");
        }
        if (from != null && to != null) {
            if (to.isBefore(from)) throw new BadRequestException("Khoang thoi gian khong hop le.");
            if (Duration.between(from, to).compareTo(Duration.ofDays(7)) > 0) {
                throw new BadRequestException("Khoang thoi gian truy van toi da la 7 ngay.");
            }
        }
    }

    private String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private String validatedUserId(String value) {
        String normalized = trimToNull(value);
        if (normalized != null && normalized.length() > 64) {
            throw new BadRequestException("Ma tai khoan qua dai.");
        }
        return normalized;
    }

    @Transactional(readOnly = true)
    public PageResponse<SiemDtos.Incident> includeAssignedAnalysts(PageResponse<SiemDtos.Incident> page) {
        var assignees = assignedAnalysts(page.content().stream().map(SiemDtos.Incident::assigneeUserId)
                .filter(java.util.Objects::nonNull).distinct().toList());
        return new PageResponse<>(page.content().stream().map(value -> value.withAssignedAnalyst(
                value.assigneeUserId()==null ? null : assignees.get(value.assigneeUserId()))).toList(), page.page(), page.size(), page.totalElements(),
                page.totalPages(), page.hasNext());
    }

    @Transactional(readOnly = true)
    public SiemDtos.IncidentDetail includeAssignedAnalyst(SiemDtos.IncidentDetail detail) {
        String id = detail.incident().assigneeUserId();
        return id == null ? detail : new SiemDtos.IncidentDetail(
                detail.incident().withAssignedAnalyst(assignedAnalysts(List.of(id)).get(id)), detail.notes());
    }

    private Map<String, SiemDtos.AssignedAnalyst> assignedAnalysts(List<String> ids) {
        if (ids.isEmpty()) return Map.of();
        Map<String, SiemDtos.AssignedAnalyst> result = new HashMap<>();
        for (var user : userRepository.findAnalystIdentities(ids)) {
            String name = trimToNull(user.getName());
            if (name == null) name = trimToNull(user.getUsername());
            String role = CurrentUserPrincipal.toAuthority(user.getRole()).replaceFirst("^ROLE_", "");
            if (name != null) result.put(user.getId(), new SiemDtos.AssignedAnalyst(name, role));
        }
        return result;
    }

    private SiemDtos.Incident toIncident(SiemIncident value) {
        return new SiemDtos.Incident(value.getId(), value.getTitle(), value.getServiceId(), value.getRuleId(),
                value.getSourceIp(), value.getBucketStart(), value.getSourceSeverity(), value.getScore(),
                value.getSeverity(), value.getClassification(), value.getClassificationReason(),
                Boolean.TRUE.equals(value.getMissingData()), value.getStatus(), value.getConclusion(),
                value.getAssigneeUserId(), Boolean.TRUE.equals(value.getManualInvestigateOverride()),
                value.getAlertCount(), value.getDistinctRuleCount(), value.getFirstSeen(), value.getLastSeen(),
                value.getUpdatedAt(), value.getVersion(), value.getQueueTier(), value.getOrigin(),
                value.getTargetUserId(), value.getDetectorModelVersion(), value.getNature());
    }

    private SiemDtos.Note toNote(SiemIncidentNote value) {
        return new SiemDtos.Note(value.getId(), value.getAuthorUserId(), value.getContent(), value.getCreatedAt());
    }

    private SiemDtos.History toHistory(SiemIncidentHistory value) {
        return new SiemDtos.History(value.getId(), value.getIncidentId(), value.getActorUserId(), value.getAction(),
                value.getPreviousValue(), value.getNewValue(), value.getDetail(), value.getCreatedAt());
    }

    private SiemDtos.AlertRef toAlertRef(SiemAlertRef value) {
        return new SiemDtos.AlertRef(value.getId(), value.getElasticAlertId(), value.getElasticIndex(),
                value.getRuleId(), value.getServiceId(), value.getSourceIp(), value.getSourceSeverity(),
                value.getEventTimestamp());
    }

    private SiemDtos.TestWindow toTestWindow(SiemTestWindow value) {
        return new SiemDtos.TestWindow(value.getId(), value.getName(), value.getSourceIp(), value.getServiceId(),
                value.getStartsAt(), value.getEndsAt(), Boolean.TRUE.equals(value.getActive()),
                value.getCreatedByUserId(), value.getCreatedAt(), value.getUpdatedAt(), value.getVersion());
    }
}
