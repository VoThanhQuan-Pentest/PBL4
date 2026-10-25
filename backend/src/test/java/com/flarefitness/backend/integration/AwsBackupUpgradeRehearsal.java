package com.flarefitness.backend.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import org.flywaydb.core.Flyway;

/** Opt-in standalone test helper; never starts the application or accepts a database URL. */
public final class AwsBackupUpgradeRehearsal {
    private static final Map<String, Set<String>> ADDED_COLUMNS = Map.of(
            "siem_account_behavior_windows", Set.of("personal_feature_schema_version",
                    "personal_feature_vector_json", "scored_feature_schema_version",
                    "contextual_feature_schema_version", "contextual_feature_vector_json",
                    "session_endpoint_feature_schema_version", "session_endpoint_feature_vector_json"),
            "siem_security_events", Set.of("telemetry_contract_version", "endpoint_category", "session_pseudonym", "session_issued_at"),
            "siem_incidents", Set.of("detector_model_version", "incident_nature"),
            "siem_ueba_model_jobs", Set.of("feature_schema_version", "recipe_id", "dataset_id",
                    "dataset_manifest_sha256", "model_sha256", "evaluation_worker_job_id",
                    "evaluation_dataset_id", "evaluation_dataset_sha256", "evaluation_status",
                    "quality_gate", "evaluation_summary_json", "activation_worker_job_id",
                    "activation_status", "activation_requested_by_user_id"));
    private static final Set<String> ADDED_TABLES = Set.of(
            "siem_ueba_shadow_runs", "siem_ueba_shadow_deliveries");
    private static final Map<String, Set<String>> ADDED_COLUMNS_FROM_31 = Map.of(
            "siem_account_behavior_windows", Set.of("contextual_feature_schema_version",
                    "contextual_feature_vector_json", "session_endpoint_feature_schema_version",
                    "session_endpoint_feature_vector_json"),
            "siem_security_events", Set.of("telemetry_contract_version", "endpoint_category",
                    "session_pseudonym", "session_issued_at"),
            "siem_incidents", Set.of("detector_model_version", "incident_nature"));
    private static final String URL = "jdbc:mysql://127.0.0.1:3306/flare_rehearsal"
            + "?useSSL=false&allowPublicKeyRetrieval=true&connectionTimeZone=UTC";

    private record TableSnapshot(Map<String, String> columns, long rows, String digest) {}

    private AwsBackupUpgradeRehearsal() {}

    public static void main(String[] args) throws Exception {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("passed", false);
        evidence.put("scope", "LOCAL_ONLY_IMMUTABLE_BACKUP_TO_36");
        evidence.put("observed_at", Instant.now().toString());
        String stage = "DISPOSABLE_CONNECTION";
        Path output = Path.of("/evidence/helper.json");
        try {
            require(args.length == 0, "No arguments or external database URLs permitted");
            require("DISPOSABLE_LOCAL_ONLY".equals(System.getenv("REHEARSAL_MODE")), "Opt-in required");
            String sourceVersion = System.getenv("REHEARSAL_SOURCE_SCHEMA");
            require("27".equals(sourceVersion) || "31".equals(sourceVersion),
                    "Explicit supported source schema 27 or 31 required");
            boolean schema27 = "27".equals(sourceVersion);
            boolean includeE2eSeed = "true".equals(System.getenv("REHEARSAL_INCLUDE_E2E_SEED"));
            int sourceVersionNumber = Integer.parseInt(sourceVersion);
            int expectedMigrations = 36 - sourceVersionNumber;
            Map<String, Set<String>> addedColumns = schema27 ? ADDED_COLUMNS : ADDED_COLUMNS_FROM_31;
            Set<String> addedTables = schema27 ? ADDED_TABLES : Set.of();
            evidence.put("scope", "LOCAL_ONLY_IMMUTABLE_BACKUP_SCHEMA_" + sourceVersion + "_TO_36");
            evidence.put("e2e_repeatable_location_included", includeE2eSeed);
            String password = System.getenv("MYSQL_ROOT_PASSWORD");
            require(password != null && password.length() >= 32, "Private credential required");
            List<String> locations = new ArrayList<>(List.of("filesystem:/rehearsal/migrations"));
            if (includeE2eSeed) locations.add("filesystem:/rehearsal/e2e-seed");
            Flyway flyway = Flyway.configure().dataSource(URL, "root", password)
                    .locations(locations.toArray(String[]::new)).cleanDisabled(true)
                    .baselineOnMigrate(false).validateOnMigrate(true).load();
            // Before upgrade, validate the imported applied history at its exact version.
            // Above-target migrations are not checksum exceptions; the unrestricted migrate
            // validates those migrations itself and the target-36 validate checks them again.
            Flyway sourceValidator = Flyway.configure().configuration(flyway.getConfiguration()).target(sourceVersion).load();
            try (Connection connection = DriverManager.getConnection(URL, "root", password)) {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("SET time_zone = '+00:00'");
                }
                stage = "SOURCE_VALIDATION";
                require(sourceVersion.equals(flyway.info().current().getVersion().getVersion()),
                        "Source version differs from the explicit rehearsal source");
                var validation = sourceValidator.validateWithResult();
                evidence.put("source_flyway_validation_successful", validation.validationSuccessful);
                evidence.put("source_flyway_validation_errors", validation.invalidMigrations.stream().map(invalid ->
                        Map.of("version", invalid.version, "error_code", invalid.errorDetails.errorCode.toString())).toList());
                evidence.put("applied_migration_checksum_mismatches", java.util.Arrays.stream(flyway.info().all())
                        .filter(info -> info.isApplied() && !info.isChecksumMatching())
                        .map(info -> Map.of("version", info.getVersion().getVersion(),
                                "applied_checksum", info.getAppliedChecksum(),
                                "resolved_checksum", info.getResolvedChecksum())).toList());
                sourceValidator.validate(); // No repair, baseline, checksum override, or ignore-pattern override.
                require(flyway.info().pending().length == expectedMigrations,
                        "Pending migration count differs from the source-to-target range");
                Set<String> sourceTables = tables(connection);
                require(sourceTables.size() == (schema27 ? 43 : 45), "Unexpected source base-table count");
                Set<String> legacyIds = strings(connection, "SELECT id FROM siem_ueba_model_jobs "
                        + "WHERE activated_at IS NOT NULL AND status IN ('ACTIVE', 'RETIRED')");
                Set<String> primaryIds = strings(connection,
                        "SELECT id FROM siem_ueba_model_jobs WHERE status = 'ACTIVE'");
                require(primaryIds.size() == 1 && legacyIds.containsAll(primaryIds), "One qualified active primary required");
                Map<String, String> modelColumns = columns(connection, "siem_ueba_model_jobs");
                boolean autoTimestamp = modelColumns.get("updated_at").toLowerCase().contains("on update current_timestamp");
                Set<String> normalizedIds = schema27 && autoTimestamp ? legacyIds : Set.of();
                Map<String, TableSnapshot> before = snapshot(connection, sourceTables, normalizedIds);
                long historyRows = before.get("flyway_schema_history").rows();
                long expectedRepeatableRows = includeE2eSeed ? 1 : 0;
                long repeatableRows = count(connection, "SELECT COUNT(*) FROM flyway_schema_history "
                        + "WHERE version IS NULL AND success = 1");
                require(repeatableRows == expectedRepeatableRows,
                        "Applied repeatable migration count differs from the explicit source environment");
                require(historyRows == sourceVersionNumber + expectedRepeatableRows,
                        "Applied Flyway history row count differs from source version");
                String primaryBefore = rowDigest(connection, "siem_ueba_model_jobs", modelColumns.keySet(),
                        normalizedIds, " WHERE status = 'ACTIVE'");
                evidence.put("source_version", sourceVersion);
                evidence.put("source_table_count", sourceTables.size());
                evidence.put("source_repeatable_migration_count", repeatableRows);
                evidence.put("active_primary_id_sha256", textDigest(String.join("\n", primaryIds)));
                evidence.put("legacy_restore_model_count", legacyIds.size());
                evidence.put("normalized_updated_at_column",
                        schema27 && autoTimestamp ? "siem_ueba_model_jobs.updated_at" : null);
                evidence.put("normalization_scope", schema27 && autoTimestamp
                        ? "ONLY_PREEXISTING_ACTIVATED_ACTIVE_OR_RETIRED_ROWS_WITH_ON_UPDATE_TIMESTAMP"
                        : "NONE_ALL_ORIGINAL_COLUMN_VALUES_MUST_MATCH_EXACTLY");
                stage = "CURRENT_FLYWAY_MIGRATE";
                Instant migrationStarted = Instant.now();
                int migrated = flyway.migrate().migrationsExecuted;
                require(migrated == expectedMigrations, "All pending migrations must execute exactly once");
                require("36".equals(flyway.info().current().getVersion().getVersion()), "Target version is not 36");
                flyway.validate();
                stage = "PRESERVATION_VERIFICATION";
                Set<String> targetTables = tables(connection);
                Set<String> expectedTables = new TreeSet<>(sourceTables);
                expectedTables.addAll(addedTables);
                require(targetTables.equals(expectedTables), "Unexpected added or removed base table");
                Map<String, Object> tableEvidence = new TreeMap<>();
                for (String table : sourceTables) {
                    TableSnapshot source = before.get(table);
                    Map<String, String> targetColumns = columns(connection, table);
                    Set<String> expectedColumns = new TreeSet<>(source.columns().keySet());
                    expectedColumns.addAll(addedColumns.getOrDefault(table, Set.of()));
                    require(targetColumns.keySet().equals(expectedColumns), "Unexpected columns: " + table);
                    for (String column : source.columns().keySet()) {
                        require(source.columns().get(column).equals(targetColumns.get(column)),
                                "Original column definition changed: " + table + "." + column);
                    }
                    String predicate = table.equals("flyway_schema_history")
                            ? " WHERE installed_rank <= " + historyRows : "";
                    long afterRows = count(connection, "SELECT COUNT(*) FROM " + quote(table) + predicate);
                    String afterDigest = rowDigest(connection, table, source.columns().keySet(), normalizedIds, predicate);
                    require(source.rows() == afterRows && source.digest().equals(afterDigest),
                            "Original data changed: " + table);
                    tableEvidence.put(table, Map.of("original_rows", source.rows(),
                            "original_columns", source.columns().size(), "before_sha256", source.digest(),
                            "after_sha256", afterDigest, "preserved", true));
                }
                for (String table : addedTables) {
                    require(count(connection, "SELECT COUNT(*) FROM " + quote(table)) == 0,
                            "New bookkeeping tables must be empty");
                }
                require(count(connection, "SELECT COUNT(*) FROM flyway_schema_history") == historyRows + migrated,
                        "Flyway history must contain exactly one entry per executed migration");
                String featureBackfillPredicate = schema27
                        ? "personal_feature_schema_version IS NOT NULL OR personal_feature_vector_json IS NOT NULL "
                                + "OR scored_feature_schema_version IS NOT NULL OR contextual_feature_schema_version IS NOT NULL "
                                + "OR contextual_feature_vector_json IS NOT NULL OR session_endpoint_feature_schema_version IS NOT NULL "
                                + "OR session_endpoint_feature_vector_json IS NOT NULL"
                        : "contextual_feature_schema_version IS NOT NULL OR contextual_feature_vector_json IS NOT NULL "
                                + "OR session_endpoint_feature_schema_version IS NOT NULL "
                                + "OR session_endpoint_feature_vector_json IS NOT NULL";
                require(count(connection, "SELECT COUNT(*) FROM siem_account_behavior_windows WHERE "
                        + featureBackfillPredicate) == 0, "Historical feature backfill is forbidden");
                require(count(connection, "SELECT COUNT(*) FROM siem_security_events WHERE telemetry_contract_version IS NOT NULL "
                        + "OR endpoint_category IS NOT NULL OR session_pseudonym IS NOT NULL OR session_issued_at IS NOT NULL") == 0,
                        "Historical session/endpoint metadata must not be fabricated");
                require(count(connection, "SELECT COUNT(*) FROM siem_incidents WHERE detector_model_version IS NOT NULL "
                        + "OR incident_nature <> 'UNKNOWN'") == 0,
                        "New incident model metadata must not be fabricated during migration");
                if (schema27) {
                    require(count(connection, "SELECT COUNT(*) FROM siem_ueba_model_jobs WHERE "
                            + "feature_schema_version <> 1 OR recipe_id <> 'legacy-v1' OR dataset_id IS NOT NULL "
                            + "OR dataset_manifest_sha256 IS NOT NULL OR model_sha256 IS NOT NULL "
                            + "OR evaluation_worker_job_id IS NOT NULL OR evaluation_dataset_id IS NOT NULL "
                            + "OR evaluation_dataset_sha256 IS NOT NULL OR evaluation_status <> 'NOT_RUN' "
                            + "OR evaluation_summary_json IS NOT NULL OR activation_worker_job_id IS NOT NULL "
                            + "OR activation_status <> 'NOT_RUN' OR activation_requested_by_user_id IS NOT NULL") == 0,
                            "New model metadata must retain legacy defaults, not fabricate evaluation or activation");
                    require(strings(connection, "SELECT id FROM siem_ueba_model_jobs WHERE quality_gate = 'LEGACY_RESTORE'")
                            .equals(legacyIds), "LEGACY_RESTORE must identify exactly the preexisting qualified models");
                    require(count(connection, "SELECT COUNT(*) FROM siem_ueba_model_jobs WHERE "
                            + "quality_gate NOT IN ('NOT_RUN', 'LEGACY_RESTORE')") == 0,
                            "No fabricated quality PASS permitted");
                }
                require(strings(connection, "SELECT id FROM siem_ueba_model_jobs WHERE status = 'ACTIVE'")
                        .equals(primaryIds), "Original primary identity and ACTIVE status must remain");
                String primaryAfter = rowDigest(connection, "siem_ueba_model_jobs", modelColumns.keySet(),
                        normalizedIds, " WHERE status = 'ACTIVE'");
                require(primaryBefore.equals(primaryAfter), "Original primary payload changed");
                long timestampChanges = schema27 && autoTimestamp
                        ? verifyTimestampChanges(connection, legacyIds, migrationStarted) : 0;
                Map<String, TableSnapshot> after = snapshot(connection, targetTables, Set.of());
                stage = "IDEMPOTENT_SECOND_MIGRATE";
                require(flyway.migrate().migrationsExecuted == 0, "Second migration must be a no-op");
                flyway.validate();
                require(after.equals(snapshot(connection, targetTables, Set.of())),
                        "Second migration changed data or column definitions");
                evidence.put("target_version", "36");
                evidence.put("target_table_count", targetTables.size());
                evidence.put("migrations_executed", migrated);
                evidence.put("second_migrate_executed", 0);
                evidence.put("primary_status", "ACTIVE");
                evidence.put("primary_feature_schema_versions",
                        strings(connection, "SELECT DISTINCT feature_schema_version FROM siem_ueba_model_jobs WHERE status = 'ACTIVE'"));
                evidence.put("primary_quality_gates",
                        strings(connection, "SELECT DISTINCT quality_gate FROM siem_ueba_model_jobs WHERE status = 'ACTIVE'"));
                evidence.put("primary_original_payload_sha256", primaryAfter);
                evidence.put("migration_time_updated_at_rows", timestampChanges);
                evidence.put("documented_new_columns", addedColumns);
                evidence.put("documented_new_empty_tables", addedTables);
                evidence.put("tables", tableEvidence);
                evidence.put("passed", true);
                stage = "COMPLETE";
            }
        } catch (Exception failure) {
            evidence.put("failure_class", failure.getClass().getSimpleName());
            if (failure instanceof CheckFailure) evidence.put("failed_check", failure.getMessage());
            // Exception messages/SQL/private row values and credentials never enter evidence or stdout.
        }
        evidence.put("stage", stage);
        Files.writeString(output, new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(evidence),
                StandardOpenOption.CREATE_NEW);
        if (!Boolean.TRUE.equals(evidence.get("passed"))) {
            System.err.println("Local backup upgrade rehearsal failed at " + stage + "; private details omitted");
            System.exit(1);
        }
    }

    private static Map<String, TableSnapshot> snapshot(Connection connection, Set<String> tables,
            Set<String> normalizedModelIds) throws Exception {
        Map<String, TableSnapshot> result = new TreeMap<>();
        for (String table : tables) {
            Map<String, String> columns = columns(connection, table);
            result.put(table, new TableSnapshot(columns,
                    count(connection, "SELECT COUNT(*) FROM " + quote(table)),
                    rowDigest(connection, table, columns.keySet(), normalizedModelIds, "")));
        }
        return result;
    }

    private static Map<String, String> columns(Connection connection, String table) throws Exception {
        Map<String, String> result = new TreeMap<>();
        try (var statement = connection.prepareStatement("SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, "
                + "COLUMN_DEFAULT, CHARACTER_SET_NAME, COLLATION_NAME, EXTRA FROM information_schema.columns "
                + "WHERE table_schema = DATABASE() AND table_name = ? ORDER BY ORDINAL_POSITION")) {
            statement.setString(1, table);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    List<String> definition = new ArrayList<>();
                    for (int index = 2; index <= 7; index++) definition.add(rows.getString(index));
                    result.put(rows.getString(1), new ObjectMapper().writeValueAsString(definition));
                }
            }
        }
        return result;
    }

    private static String rowDigest(Connection connection, String table, Set<String> columns,
            Set<String> normalizedModelIds, String predicate) throws Exception {
        List<String> names = new ArrayList<>(columns);
        List<String> rowHashes = new ArrayList<>();
        String select = String.join(",", names.stream().map(AwsBackupUpgradeRehearsal::quote).toList());
        try (Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery("SELECT " + select + " FROM " + quote(table) + predicate)) {
            while (rows.next()) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                boolean normalized = table.equals("siem_ueba_model_jobs")
                        && normalizedModelIds.contains(rows.getString("id"));
                for (String name : names) {
                    if (normalized && name.equals("updated_at")) continue;
                    byte[] value = rows.getBytes(name);
                    digest.update(ByteBuffer.allocate(4).putInt(value == null ? -1 : value.length).array());
                    if (value != null) digest.update(value);
                }
                rowHashes.add(HexFormat.of().formatHex(digest.digest()));
            }
        }
        rowHashes.sort(String::compareTo);
        return textDigest(String.join("\n", rowHashes));
    }

    private static long verifyTimestampChanges(Connection connection, Set<String> legacyIds,
            Instant migrationStarted) throws Exception {
        long rows = 0;
        try (Statement statement = connection.createStatement(); ResultSet result = statement.executeQuery(
                "SELECT id, updated_at FROM siem_ueba_model_jobs WHERE quality_gate = 'LEGACY_RESTORE'")) {
            while (result.next()) {
                require(legacyIds.contains(result.getString(1)), "Unexpected normalized timestamp row");
                Instant updated = result.getTimestamp(2).toInstant();
                require(!updated.isBefore(migrationStarted.minusSeconds(1)) && !updated.isAfter(Instant.now().plusSeconds(1)),
                        "ON UPDATE timestamp is not within the actual migration interval");
                rows++;
            }
        }
        return rows;
    }

    private static Set<String> tables(Connection connection) throws Exception {
        return strings(connection, "SELECT TABLE_NAME FROM information_schema.tables "
                + "WHERE table_schema = DATABASE() AND TABLE_TYPE = 'BASE TABLE'");
    }

    private static Set<String> strings(Connection connection, String sql) throws Exception {
        Set<String> result = new TreeSet<>();
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            while (rows.next()) result.add(rows.getString(1));
        }
        return result;
    }

    private static long count(Connection connection, String sql) throws Exception {
        try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery(sql)) {
            require(rows.next(), "Count result required");
            return rows.getLong(1);
        }
    }

    private static String quote(String identifier) {
        require(identifier.matches("[a-zA-Z0-9_]+"), "Unsafe SQL identifier");
        return "`" + identifier + "`";
    }

    private static String textDigest(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new CheckFailure(message);
    }

    private static final class CheckFailure extends IllegalStateException {
        private CheckFailure(String message) { super(message); }
    }
}
