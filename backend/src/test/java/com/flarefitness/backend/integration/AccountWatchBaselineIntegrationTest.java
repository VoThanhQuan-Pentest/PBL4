package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.siem.SiemAccountBehaviorWindow;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.siem.SiemAccountBehaviorWindowRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.siem.AccountBehaviorFeatures;
import com.flarefitness.backend.service.siem.SiemAccountWatchService;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AccountWatchBaselineIntegrationTest extends ContainerizedIntegrationTest {
    private static final LocalDateTime AS_OF = LocalDateTime.of(2035, 1, 30, 12, 0);
    private static final List<String> ROLES = List.of("ADMIN", "SOC L1", "SOC L2", "CUSTOMER");
    @Autowired private UserRepository users;
    @Autowired private SiemAccountBehaviorWindowRepository windows;
    @Autowired private SiemAccountWatchService watch;
    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper json;

    static Stream<Arguments> accountCases() {
        return IntStream.range(0, 6).boxed().flatMap(cohort ->
                IntStream.of(-1, 0, 29, 44, 45).boxed().flatMap(risk ->
                        Stream.of("RISK", "BASELINE_GAPS", "ALL").flatMap(view ->
                                ROLES.stream().map(role -> Arguments.of(cohort, risk, view, role)))));
    }

    @ParameterizedTest(name = "cohort={0},risk={1},view={2},role={3}")
    @MethodSource("accountCases")
    void exposesCoverageWithoutTurningMissingBaselineIntoRisk(int cohort, int risk, String view, String role) throws Exception {
        String id = "000-baseline-" + UUID.randomUUID();
        users.save(customer(id));
        int count = new int[]{0, 1, 29, 30, 31, 30}[cohort];
        List<SiemAccountBehaviorWindow> fixture = new ArrayList<>();
        for (int index = 0; index < count; index++) fixture.add(window(id,
                AS_OF.minusDays(cohort == 5 ? 16 : 2).plusMinutes(index * 15L), null, true));
        // Risk in the requested 30-day range need not imply recent trusted baseline history.
        if (risk >= 0) fixture.add(window(id, AS_OF.minusDays(15), risk, false));
        windows.saveAllAndFlush(fixture);
        var request = get("/api/siem/accounts/watchlist").with(authentication(actor(role)))
                .param("from", AS_OF.minusDays(30).toString()).param("to", AS_OF.toString())
                .param("size", "100").param("view", view);
        if ("CUSTOMER".equals(role)) { mvc.perform(request).andExpect(status().isForbidden()); return; }
        String body = mvc.perform(request).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        JsonNode found = null;
        for (JsonNode item : json.readTree(body).path("content")) {
            if (id.equals(item.path("account_id").asText())) found = item;
        }
        boolean ready = cohort == 3 || cohort == 4;
        boolean included = "ALL".equals(view) || "RISK".equals(view) && risk >= 45
                || "BASELINE_GAPS".equals(view) && !ready;
        if (!included) { assertThat(found).isNull(); return; }
        assertThat(found).isNotNull();
        assertThat(found.path("baseline_status").asText()).isEqualTo(ready ? "READY"
                : cohort == 0 || cohort == 5 ? "NO_DATA" : "INSUFFICIENT_HISTORY");
        assertThat(found.path("trusted_window_count").asInt()).isEqualTo(cohort == 5 ? 0 : count);
        assertThat(found.path("risk_available").asBoolean()).isEqualTo(risk >= 0);
        assertThat(found.path("required_window_count").asInt()).isEqualTo(30);
        assertThat(found.path("history_days").asInt()).isEqualTo(14);
        assertThat(found.path("maximum_risk").asInt()).isEqualTo(Math.max(0, risk));
        assertThat(body).doesNotContain("fixture-secret-" + id, "private-" + id + "@example.invalid");
    }

    static Stream<Arguments> invalidCases() {
        return IntStream.range(0, 10).boxed().flatMap(input -> ROLES.stream().map(role -> Arguments.of(input, role)));
    }

    @ParameterizedTest(name = "invalid={0},role={1}")
    @MethodSource("invalidCases")
    void rejectsInvalidBoundsAndKeepsAuthorizationFirst(int input, String role) throws Exception {
        var request = get("/api/siem/accounts/watchlist").with(authentication(actor(role)));
        Map<String, String> params = new java.util.HashMap<>(Map.of(
                "from", AS_OF.minusDays(1).toString(), "to", AS_OF.toString(), "page", "0", "size", "50"));
        switch (input) {
            case 0 -> params.put("page", "-1");
            case 1 -> params.put("size", "0");
            case 2 -> params.put("size", "101");
            case 3 -> params.put("from", AS_OF.toString());
            case 4 -> params.put("from", AS_OF.plusHours(1).toString());
            case 5 -> params.put("from", AS_OF.minusDays(31).toString());
            case 6 -> params.remove("from");
            case 7 -> params.put("from", "not-a-date");
            case 8 -> params.put("view", "UNKNOWN");
            case 9 -> params.put("page", "not-an-integer");
            default -> throw new IllegalArgumentException();
        }
        params.forEach(request::param);
        mvc.perform(request).andExpect("CUSTOMER".equals(role) ? status().isForbidden() : status().isBadRequest());
    }

    @Test
    void enumeratesFiveHundredCustomersAcrossPagesWithoutPiiOrDuplicateRows() {
        String prefix = "000-page-" + UUID.randomUUID().toString().substring(0, 8) + "-";
        users.saveAllAndFlush(IntStream.range(0, 500).mapToObj(index -> customer(prefix + "%03d".formatted(index))).toList());
        HashSet<String> found = new HashSet<>();
        int page = 0;
        while (true) {
            var result = watch.watchlist(AS_OF.minusDays(1), AS_OF, page++, 50, SiemDtos.AccountWatchView.ALL);
            for (var item : result.content()) {
                if (item.accountId().startsWith(prefix)) {
                    assertThat(found.add(item.accountId())).isTrue();
                    assertThat(item.baselineStatus()).isEqualTo("NO_DATA");
                    assertThat(item.riskAvailable()).isFalse();
                }
            }
            if (!result.hasNext()) break;
            assertThat(page).isLessThan(100);
        }
        assertThat(found).hasSize(500);
    }

    @Test
    void realHistoricalActivityMovesTwentyNineToThirtyAndDefaultViewStaysRiskOnly() {
        String id = "000-maturity-" + UUID.randomUUID();
        users.save(customer(id));
        windows.saveAllAndFlush(IntStream.range(0, 29).mapToObj(index ->
                window(id, AS_OF.minusDays(2).plusMinutes(index * 15L), null, true)).toList());
        assertThat(watch.watchlist(AS_OF.minusDays(1), AS_OF, 0, 100, SiemDtos.AccountWatchView.BASELINE_GAPS)
                .content()).anyMatch(item -> id.equals(item.accountId()) && item.trustedWindowCount() == 29);
        windows.saveAndFlush(window(id, AS_OF.minusHours(1), null, true));
        assertThat(watch.watchlist(AS_OF.minusDays(1), AS_OF, 0, 100, SiemDtos.AccountWatchView.BASELINE_GAPS)
                .content()).noneMatch(item -> id.equals(item.accountId()));
        assertThat(watch.watchlist(AS_OF.minusDays(1), AS_OF, 0, 100).content())
                .noneMatch(item -> id.equals(item.accountId()));
    }

    @Test
    void anonymousCannotReadAccountInventory() throws Exception {
        mvc.perform(get("/api/siem/accounts/watchlist").param("from", AS_OF.minusDays(1).toString())
                .param("to", AS_OF.toString())).andExpect(status().isUnauthorized());
    }

    private static UsernamePasswordAuthenticationToken actor(String role) {
        User user = customer("baseline-test-operator");
        user.setRole(role);
        var principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }

    private static User customer(String id) {
        User user = new User();
        user.setId(id);
        user.setUsername(id);
        user.setHoTen("Isolated baseline fixture");
        user.setPassword("fixture-secret-" + id);
        user.setEmail("private-" + id + "@example.invalid");
        user.setRole("CUSTOMER");
        user.setStatus("Hoat dong");
        user.setDeleted(false);
        user.setCreatedAt(AS_OF.minusDays(30));
        return user;
    }

    private static SiemAccountBehaviorWindow window(String account, LocalDateTime start, Integer risk, boolean trusted) {
        var window = new SiemAccountBehaviorWindow();
        window.setId("baseline-window-" + UUID.randomUUID());
        window.setAccountId(account);
        window.setWindowStart(start);
        window.setWindowEnd(start.plusMinutes(15));
        window.setCreatedAt(start);
        window.replaceFeatures(new AccountBehaviorFeatures.Vector(1,
                List.of(4.0, 0.0, 0.0, trusted ? 0.0 : 1.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0)),
                6, false, "198.51.100.1", "CHROMIUM", "NORMAL", AS_OF);
        if (risk != null) window.recordAssessment(new SiemAccountBehaviorWindow.AccountRiskAssessment(null, null, risk, "fixture"), AS_OF);
        return window;
    }
}
