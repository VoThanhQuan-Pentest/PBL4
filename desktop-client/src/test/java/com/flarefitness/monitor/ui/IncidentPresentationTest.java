package com.flarefitness.monitor.ui;

import static org.junit.jupiter.api.Assertions.*;
import com.flarefitness.monitor.model.SiemModels;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class IncidentPresentationTest {
    public static SiemModels.Incident incident(String rule, String title, String reason, String assignee,
                                               SiemModels.AssignedAnalyst analyst, String status) {
        return incident(rule,title,reason,assignee,analyst,status,"CORRELATION");
    }
    static SiemModels.Incident incident(String rule, String title, String reason, String assignee,
                                       SiemModels.AssignedAnalyst analyst, String status, String origin) {
        var at = LocalDateTime.of(2026, 10, 24, 1, 2, 3);
        return new SiemModels.Incident("a", title, "flare", rule, "192.0.2.25", at, "HIGH", 80,
                "HIGH", "INVESTIGATE", reason, false, status, "UNREVIEWED", assignee, false, 3, 1,
                at, at.plusHours(4), at.plusDays(1), 1, "L2", origin, null, null,
                "ELASTIC_DETECTION", analyst);
    }
    private static SiemModels.ObservedGroup group(String... values) {
        return new SiemModels.ObservedGroup(java.util.Arrays.stream(values)
                .map(value -> new SiemModels.ObservedValue(value, "logs-nginx.access-lab", "source")).toList(), false);
    }
    @Test void detectorIdentitySuppliesConciseNameWithoutCaseIdsOrPolicyDetails() {
        var incident = incident("AUTH_BRUTE_TARGET", "Điều tra tài khoản · AUTH_BRUTE_TARGET", "", null, null, "NEW");
        assertEquals("Sign in brute force", IncidentPresentation.scenario(incident));
        assertEquals("Thực hành quy trình SOC", IncidentPresentation.scenario(incident("SOC_DEMO_WORKFLOW",
                "SOC-PRACTICE-L2 20261024-c83c78", "DEMO_ONLY_WORKFLOW_FIXTURE", null, null, "NEW")));
    }
    @Test void webAttackTypeAndEndpointComeFromObservedEvidenceWithoutGuessing() {
        var incident = incident("flare-lab-high-web-heuristic", "Flare Lab: SQLi/XSS/traversal heuristic", "", null, null, "NEW");
        assertEquals("SQL injection in /api/products", IncidentPresentation.scenario(incident,
                Map.of("flare.detection.type", group("sql_injection_signal"), "url.path", group("/api/products"))));
        assertEquals("Dấu hiệu SQL injection / XSS / traversal", IncidentPresentation.scenario(incident));
        assertEquals("Dấu hiệu SQL injection / XSS / traversal", IncidentPresentation.scenario(incident,
                Map.of("flare.detection.type", group("sql_injection_signal", "xss_signal"))));
        assertEquals("SQL injection", IncidentPresentation.scenario(incident,
                Map.of("flare.detection.type", group("sql_injection_signal"), "url.path", group("/api/products?token=hidden"))));
    }
    @Test void assigneeUsesActualNameAndRoleInsteadOfIncidentTierOrAccountId() {
        assertEquals("Chưa có người nhận", IncidentPresentation.assignee(incident("rule", "Case", "", null, null, "NEW")));
        assertEquals("James-SOC_L1", IncidentPresentation.assignee(incident("rule", "Case", "", "opaque-id",
                new SiemModels.AssignedAnalyst("James", "SOC_L1"), "IN_PROGRESS")));
        assertEquals("Chưa rõ tên người nhận", IncidentPresentation.assignee(incident("rule", "Case", "", "opaque-id", null, "IN_PROGRESS")));
    }
    @Test void occurrenceTimeUsesFirstEventAndVietnamTimeRegardlessOfLaterUpdates() {
        assertEquals("24/10 08:02:03", IncidentPresentation.occurredAt(incident("rule", "Case", "", null, null, "NEW")));
    }
    @Test void incompleteEvidenceCannotChooseOneHeuristicAttackOrEndpoint() {
        var item=incident("flare-lab-high-web-heuristic","Flare Lab: web heuristic","",null,null,"NEW");
        var observed=Map.of("flare.detection.type",group("sql_injection_signal"),"url.path",group("/api/products"));
        assertEquals("Dấu hiệu SQL injection / XSS / traversal",IncidentPresentation.scenario(item,observed,"PARTIAL"));
        var signature=incident("FLARE_PREVENTION_SIGNATURE","Confirmed SQLi attack signature blocked","",null,null,"NEW");
        assertEquals("SQL injection",IncidentPresentation.scenario(signature,observed,"PARTIAL"));
    }
    @Test void alertCreationTimeCannotPretendToBeTheSourceLogOccurrenceTime() {
        var item=incident("flare-lab-auth-bruteforce","Flare Lab: auth brute force","",null,null,"NEW","ELASTIC");
        assertEquals("Chưa có trong log",IncidentPresentation.occurredAt(item));
        assertEquals("24/10 08:00:03",IncidentPresentation.occurredAt(item,item.firstSeen().minusMinutes(2)));
        var model=incident("FLARE_UEBA_ACCOUNT_ANOMALY","Unusual account activity","",null,null,"NEW","UEBA");
        assertEquals("Chưa có trong log",IncidentPresentation.occurredAt(model));
    }
}
