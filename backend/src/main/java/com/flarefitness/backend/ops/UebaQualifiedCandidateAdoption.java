package com.flarefitness.backend.ops;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.FlareFitnessApplication;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.siem.SiemUebaModelService;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;

/** One-shot local operator command; no HTTP listener or arbitrary model upload is exposed. */
@Component
@ConditionalOnProperty(name = "siem.ueba.operator-adoption.enabled", havingValue = "true")
public final class UebaQualifiedCandidateAdoption implements CommandLineRunner {
    private static final Set<String> PACKAGE_FIELDS = Set.of("format", "schema_version", "status", "model_version",
            "data_provenance", "quality_gate", "feature_schema_version", "recipe_id", "original_dataset_id",
            "original_training_manifest_sha256", "selection_receipt_sha256", "fresh_holdout_dataset_id",
            "fresh_holdout_manifest_sha256", "holdout_split_sha256", "model_sha256", "model_state_sha256",
            "calibration_sha256", "policy_sha256", "artifact_sha256", "selection_proof", "strict_reference");

    private final SiemUebaModelService models;
    private final UserRepository users;
    private final ObjectMapper json = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build());
    private final String packageFile;
    private final String packageSha256;
    private final String adminUsername;
    private final String webApplicationType;

    public UebaQualifiedCandidateAdoption(SiemUebaModelService models, UserRepository users,
            @Value("${siem.ueba.operator-adoption.package-file:}") String packageFile,
            @Value("${siem.ueba.operator-adoption.package-sha256:}") String packageSha256,
            @Value("${siem.ueba.operator-adoption.admin-username:}") String adminUsername,
            @Value("${spring.main.web-application-type:}") String webApplicationType) {
        this.models = models;
        this.users = users;
        this.packageFile = packageFile;
        this.packageSha256 = packageSha256;
        this.adminUsername = adminUsername;
        this.webApplicationType = webApplicationType;
    }

    @Override
    public void run(String... args) throws Exception {
        if (!"none".equalsIgnoreCase(webApplicationType)) {
            throw new IllegalStateException("Adoption command requires web-application-type=none.");
        }
        byte[] raw = readPrivate(Path.of(packageFile).toAbsolutePath().normalize(), packageSha256);
        JsonNode proof = json.readTree(raw);
        if (!proof.isObject() || !fieldNames(proof).equals(PACKAGE_FIELDS)
                || !"UEBA_QUALIFIED_ADOPTION_PACKAGE_V1".equals(proof.path("format").asText())
                || !proof.path("schema_version").isIntegralNumber() || proof.path("schema_version").asInt() != 1
                || !"READY".equals(proof.path("status").asText())
                || !"DEMO_ONLY".equals(proof.path("data_provenance").asText())
                || !"PASS".equals(proof.path("quality_gate").asText())
                || proof.path("feature_schema_version").asInt(-1) != 4) {
            throw new IllegalArgumentException("Bounded qualified-adoption package is invalid.");
        }
        var user = users.findByUsernameIgnoreCase(adminUsername)
                .orElseThrow(() -> new IllegalStateException("Configured operator Admin was not found."));
        var principal = new CurrentUserPrincipal(user);
        if (!principal.isEnabled() || !"ROLE_ADMIN".equals(CurrentUserPrincipal.toAuthority(user.getRole()))) {
            throw new IllegalStateException("Candidate adoption requires an active Admin account.");
        }
        var authentication = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
        var adopted = models.adoptQualifiedCandidate(proof, authentication);
        var output = json.createObjectNode();
        output.put("status", "SUCCEEDED");
        output.put("execution_origin", "OPERATOR_ADOPTED");
        output.put("model_version", adopted.modelVersion());
        output.put("quality_gate", adopted.qualityGate());
        System.out.println(json.writeValueAsString(output));
    }

    private byte[] readPrivate(Path path, String expectedSha) throws Exception {
        if (expectedSha == null || !expectedSha.matches("[a-f0-9]{64}") || Files.isSymbolicLink(path)
                || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) > 2 * 1024 * 1024
                || !Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
                        .equals(PosixFilePermissions.fromString("rw-r-----"))) {
            throw new IllegalArgumentException("Group-private read-only operator package path required.");
        }
        Object uid = Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS);
        Object gid = Files.getAttribute(path, "unix:gid", LinkOption.NOFOLLOW_LINKS);
        Object links = Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS);
        Object processUid = Files.getAttribute(Path.of("/proc/self"), "unix:uid", LinkOption.NOFOLLOW_LINKS);
        if (!(uid instanceof Number owner) || !(processUid instanceof Number current)
                || owner.intValue() != current.intValue() || !(gid instanceof Number group) || group.intValue() != 1000
                || !(links instanceof Number count) || count.intValue() != 1) {
            throw new IllegalArgumentException("Owner-controlled single-link operator package required.");
        }
        for (Path parent = path.getParent(); parent != null; parent = parent.getParent()) {
            if (Files.isSymbolicLink(parent)) throw new IllegalArgumentException("Operator package parent cannot be a symlink.");
        }
        byte[] raw = Files.readAllBytes(path);
        String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
        if (!actual.equals(expectedSha)) throw new IllegalArgumentException("Operator package checksum mismatch.");
        return raw;
    }

    private Set<String> fieldNames(JsonNode value) {
        var names = new java.util.HashSet<String>();
        value.fieldNames().forEachRemaining(names::add);
        return names;
    }

    public static void main(String[] args) {
        if (java.util.Arrays.stream(args).noneMatch("--spring.main.web-application-type=none"::equalsIgnoreCase)) {
            System.err.println("Adoption command refused: add --spring.main.web-application-type=none.");
            System.exit(2);
        }
        try (ConfigurableApplicationContext context = new SpringApplicationBuilder(FlareFitnessApplication.class)
                .web(WebApplicationType.NONE).profiles("ueba-operator").run(args)) {
            System.exit(SpringApplication.exit(context));
        } catch (Exception failure) {
            System.err.println("Candidate adoption failed; details remain in protected operator logs.");
            System.exit(2);
        }
    }
}
