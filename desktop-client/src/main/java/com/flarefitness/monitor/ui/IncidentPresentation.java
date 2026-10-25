package com.flarefitness.monitor.ui;

import com.flarefitness.monitor.model.SiemModels;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/** Concise labels from detector identities and observed fields, never an inferred attack verdict. */
public final class IncidentPresentation {
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("dd/MM HH:mm:ss");
    private IncidentPresentation() { }

    public static String scenario(SiemModels.Incident incident) { return scenario(incident, Map.of()); }

    public static String scenario(SiemModels.Incident incident, Map<String, SiemModels.ObservedGroup> observed) {
        return scenario(incident, observed, "AVAILABLE");
    }

    public static String scenario(SiemModels.Incident incident, Map<String, SiemModels.ObservedGroup> observed, String sourceStatus) {
        if (!"AVAILABLE".equals(sourceStatus)) observed = Map.of();
        if (incident.classificationReason() != null && incident.classificationReason().contains("DEMO_ONLY_WORKFLOW_FIXTURE"))
            return "Thực hành quy trình SOC";
        String name = switch (incident.ruleId() == null ? "" : incident.ruleId()) {
            case "flare-lab-auth-bruteforce", "AUTH_BRUTE_TARGET" -> "Sign in brute force";
            case "AUTH_PASSWORD_SPRAY" -> "Password spraying";
            case "AUTH_LOGIN_SENSITIVE_CHAIN" -> "Đăng nhập và thao tác nhạy cảm bất thường";
            case "AUTH_SESSION_CONTEXT" -> "Phiên đăng nhập bất thường";
            case "AUTH_OTP_SENSITIVE_ABUSE" -> "Lạm dụng OTP / thao tác nhạy cảm";
            case "AUTH_REVOKED_SESSION_REUSE" -> "Tái sử dụng phiên đã thu hồi";
            case "FLARE_PREVENTION_HTTP_FLOOD", "flare-lab-high-request-rate" -> "HTTP flood";
            case "FLARE_PREVENTION_ENDPOINT_SCAN", "flare-lab-web-scan-404" -> "Endpoint scanning";
            case "flare-lab-scanner-user-agent" -> "Scanner User-Agent";
            case "flare-lab-server-errors" -> "Lỗi máy chủ lặp lại";
            case "flare-lab-high-web-heuristic" -> webSignal(observed);
            case "FLARE_PREVENTION_SIGNATURE" -> signature(incident.title());
            default -> "UEBA".equals(incident.origin())
                    ? ("OPERATIONAL_ANOMALY".equals(incident.nature()) ? "Bất thường vận hành" : "Bất thường hành vi tài khoản")
                    : cleanTitle(incident.title());
        };
        if (List.of("SQL injection", "XSS", "Path traversal").contains(name)) {
            var paths = observed.get("url.path");
            if (paths != null && paths.values().size() == 1 && !paths.hasMore()) {
                String path = paths.values().getFirst().value();
                // The label never includes a query string, request payload or an unbounded path.
                if (path != null && path.length() <= 80 && path.matches("/[A-Za-z0-9_./{}:-]*")) name += " in " + path;
            }
        }
        return name;
    }

    private static String webSignal(Map<String, SiemModels.ObservedGroup> observed) {
        var types = observed.get("flare.detection.type");
        if (types == null || types.hasMore() || types.values().size() != 1) return "Dấu hiệu SQL injection / XSS / traversal";
        return switch (types.values().getFirst().value()) {
            case "sql_injection_signal" -> "SQL injection";
            case "xss_signal" -> "XSS";
            case "path_traversal_signal" -> "Path traversal";
            default -> "Dấu hiệu tấn công web";
        };
    }

    private static String signature(String title) {
        return switch (title == null ? "" : title) {
            case "Confirmed SQLi attack signature blocked" -> "SQL injection";
            case "Confirmed XSS attack signature blocked" -> "XSS";
            case "Confirmed path traversal signature blocked" -> "Path traversal";
            default -> "Khớp signature tấn công";
        };
    }

    private static String cleanTitle(String title) {
        if (title == null || title.isBlank()) return "Tình huống cần điều tra";
        return title.replaceFirst("^Flare Lab:\\s*", "").replaceAll("[\\r\\n\\t]+", " ").trim();
    }

    public static String assignee(SiemModels.Incident incident) {
        if (incident.assigneeUserId() == null || incident.assigneeUserId().isBlank()) return "Chưa có người nhận";
        var analyst = incident.assignedAnalyst();
        if (analyst == null || analyst.name() == null || analyst.name().isBlank()) return "Chưa rõ tên người nhận";
        return analyst.name() + (analyst.role() == null || analyst.role().isBlank() ? "" : "-" + analyst.role());
    }

    public static String occurredAt(SiemModels.Incident incident) {
        return occurredAt(incident, null);
    }

    public static String occurredAt(SiemModels.Incident incident, java.time.LocalDateTime firstObservedAt) {
        boolean sourceTime = List.of("MANUAL", "CORRELATION", "PREVENTION").contains(incident.origin() == null ? "" : incident.origin())
                || incident.classificationReason() != null && incident.classificationReason().contains("DEMO_ONLY_WORKFLOW_FIXTURE");
        var at = sourceTime && incident.firstSeen() != null ? incident.firstSeen() : firstObservedAt;
        return at == null ? "Chưa có trong log" : TIME.format(at.atOffset(ZoneOffset.UTC)
                .atZoneSameInstant(ZoneId.of("Asia/Ho_Chi_Minh")));
    }
}
