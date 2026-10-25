package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.nio.file.Files;
import static org.mockito.Mockito.mock;
import org.springframework.jdbc.core.JdbcTemplate;

class SiemIpIntelligenceWorkerParsingTest {
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void malformedPrivateFixtureIsInvalidConfigWithoutCallingProviders(@TempDir Path directory) throws Exception {
        Path key = directory.resolve("fixture.token");
        Files.writeString(key, "Bearer not-a-real-credential");
        var worker = new SiemIpIntelligenceWorker(mock(JdbcTemplate.class), mapper,
                key.toString(), key.toString(), true,
                request -> { throw new AssertionError("Configuration check must not send HTTP"); });
        assertThat(worker.providerState("IPINFO")).isEqualTo("INVALID_CONFIG");
        assertThat(worker.providerState("ABUSEIPDB")).isEqualTo("INVALID_CONFIG");
    }

    @Test
    void freeTierIpinfoDataNeverInventsPrivacyOrAbuseFlags() throws Exception {
        var root = mapper.readTree("""
                {"ip":"8.8.8.8","asn":"AS15169","as_name":"Example Network",
                 "country_code":"US"}
                """);
        var result = SiemIpIntelligenceWorker.parseIpinfo(root, "8.8.8.8");
        assertThat(result.countryCode).isEqualTo("US");
        assertThat(result.asn).isEqualTo("AS15169");
        assertThat(result.anonymousFlag).isNull();
        assertThat(result.hostingFlag).isNull();
        assertThat(result.abuseScore).isNull();
        assertThatThrownBy(() -> SiemIpIntelligenceWorker.parseIpinfo(root, "1.1.1.1"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void abuseReportCountsAreBoundedAndTiedToRequestedIp() throws Exception {
        var root = mapper.readTree("""
                {"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":80,
                 "totalReports":4,"numDistinctUsers":2}}
                """);
        var result = SiemIpIntelligenceWorker.parseAbuse(root, "8.8.8.8");
        assertThat(result.abuseScore).isEqualTo(80);
        assertThat(result.totalReports).isEqualTo(4);
        assertThat(result.distinctReporters).isEqualTo(2);
        var invalid = mapper.readTree("""
                {"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":101}}
                """);
        assertThatThrownBy(() -> SiemIpIntelligenceWorker.parseAbuse(invalid, "8.8.8.8"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsPastedUrlsAndLabelsInsteadOfSendingThemAsTokens() {
        assertThat(SiemIpIntelligenceWorker.invalidCredential("https://api.ipinfo.io/lite/1.1.1.1?token=example"))
                .isTrue();
        assertThat(SiemIpIntelligenceWorker.invalidCredential("Bearer example"))
                .isTrue();
        assertThat(SiemIpIntelligenceWorker.invalidCredential("IPINFO_TOKEN=example"))
                .isTrue();
        assertThat(SiemIpIntelligenceWorker.invalidCredential("example-token-value"))
                .isFalse();
    }
}
