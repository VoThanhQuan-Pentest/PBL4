"""Unit contracts plus an opt-in real disposable MySQL consistency check."""
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/mysql_snapshot_inventory.py"
spec = importlib.util.spec_from_file_location("owned_inventory", SCRIPT)
inventory = importlib.util.module_from_spec(spec); sys.modules[spec.name] = inventory; spec.loader.exec_module(inventory)
IMAGE = "mysql:8.4@sha256:c831a0f11348d402b43d77453e17d770be2eef356615a2823fe0f5a0d6c8b9af"


def fixture():
    value = {"format": inventory.FORMAT, "schema_fingerprint_format": inventory.SCHEMA_FORMAT, "schema_version": "32",
             "stored_object_counts": {"views": 0, "routines": 0, "triggers": 0, "events": 0},
             "primary_models": [["owned-model-fixture", 3, "DEMO_ONLY"]],
             "tables": {"owned_rows": {"columns": ["id", "amount"], "row_count": 3,
                                         "schema_sha256": "a" * 64, "rows_sha256": "b" * 64,
                                         "raw_ddl_sha256": "d" * 64, "auto_increment_next": 4}},
             "observed_at_utc": "2026-10-02T00:00:00Z"}
    value["content_sha256"] = inventory.content_digest(value); return value


class MysqlInventoryContractTest(unittest.TestCase):
    def test_observation_time_is_not_data_identity_and_primary_binding_is(self):
        original = fixture(); later = deepcopy(original); later["observed_at_utc"] = "2026-10-03T00:00:00Z"
        self.assertTrue(inventory.compare(original, later))
        later["primary_models"][0][0] = "different-owned-model"; later["content_sha256"] = inventory.content_digest(later)
        self.assertFalse(inventory.compare(original, later))

    def test_missing_tables_changed_schema_or_same_count_different_rows_are_not_a_pass(self):
        for mutation in ("table", "columns", "schema_sha256", "rows_sha256", "row_count"):
            before = fixture(); after = deepcopy(before)
            if mutation == "table": after["tables"]["extra_owned_rows"] = after["tables"]["owned_rows"].copy()
            elif mutation == "columns": after["tables"]["owned_rows"][mutation] = ["id", "different_column"]
            elif mutation == "row_count": after["tables"]["owned_rows"][mutation] = 2
            else: after["tables"]["owned_rows"][mutation] = "c" * 64
            after["content_sha256"] = inventory.content_digest(after)
            with self.subTest(mutation=mutation): self.assertFalse(inventory.compare(before, after))

    def test_unknown_stored_objects_forged_digest_and_bool_counts_fail_closed(self):
        for mutation in ("objects", "checksum", "bool", "primary", "schema"):
            value = fixture()
            if mutation == "objects": value["stored_object_counts"]["triggers"] = 1
            elif mutation == "checksum": value["content_sha256"] = "0" * 64
            elif mutation == "bool": value["tables"]["owned_rows"]["row_count"] = True
            elif mutation == "primary": value["primary_models"][0][1] = 99
            else: value["schema_version"] = None
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): inventory.validate_inventory(value)

    def test_null_legacy_schema_is_not_invented_as_a_recorded_model_schema(self):
        value = fixture(); value["schema_version"] = "27"; value["primary_models"][0][1] = None
        value["content_sha256"] = inventory.content_digest(value)
        self.assertIsNone(inventory.validate_inventory(value)["primary_models"][0][1])

    def test_sorted_sha256_rows_preserve_duplicate_multiplicity_and_empty_tables(self):
        one, two = "a" * 64, "b" * 64
        first = inventory.rows_digest((one + "\n" + two).encode(), 2)
        self.assertNotEqual(first, inventory.rows_digest((one + "\n" + one + "\n" + two).encode(), 3))
        self.assertEqual(inventory.rows_digest(b"", 0), hashlib.sha256(b"").hexdigest())
        for data, count in (((two + "\n" + one).encode(), 2), (one.encode(), 2), (b"private row must not be accepted", 1)):
            with self.assertRaises(ValueError): inventory.rows_digest(data, count)

    def test_identifiers_cannot_inject_sql_or_escape_database_scope(self):
        for name in ("users;DROP TABLE", "../secret", "db.table", "id`FROM other", "a\nb", "-owned"):
            with self.assertRaises(ValueError): inventory.identifier(name)
        self.assertEqual(inventory.identifier("owned_table_123"), "`owned_table_123`")

    def test_raw_ddl_is_diagnostic_not_semantic_identity(self):
        before = fixture(); after = deepcopy(before)
        after["tables"]["owned_rows"]["raw_ddl_sha256"] = "e" * 64
        self.assertTrue(inventory.compare(before, after))
        self.assertTrue(inventory.compare_schema(before, after))
        for bad in (None, "not-a-hash"):
            after["tables"]["owned_rows"]["raw_ddl_sha256"] = bad
            with self.subTest(bad=bad), self.assertRaises(ValueError): inventory.validate_inventory(after)

    def test_legacy_evidence_is_readable_but_never_cross_compared_or_rewritten(self):
        current = fixture(); legacy = deepcopy(current)
        legacy["format"] = inventory.LEGACY_FORMAT
        del legacy["schema_fingerprint_format"]
        del legacy["tables"]["owned_rows"]["raw_ddl_sha256"]
        del legacy["tables"]["owned_rows"]["auto_increment_next"]
        legacy["content_sha256"] = inventory.content_digest(legacy)
        retained = deepcopy(legacy)
        self.assertTrue(inventory.compare(legacy, deepcopy(legacy)))
        for comparison in (inventory.compare, inventory.compare_schema):
            with self.assertRaises(ValueError): comparison(legacy, current)
        self.assertEqual(legacy, retained)
        drift = deepcopy(legacy); drift["tables"]["owned_rows"]["schema_sha256"] = "f" * 64
        drift["content_sha256"] = inventory.content_digest(drift)
        self.assertFalse(inventory.compare(legacy, drift))

    def test_unknown_or_missing_semantic_schema_format_fails_closed(self):
        for invalid in (None, "SHOW_CREATE_REWRITTEN_V1"):
            value = fixture(); value["schema_fingerprint_format"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError): inventory.validate_inventory(value)

    def test_auto_increment_counter_is_operational_identity_not_schema_identity(self):
        before = fixture(); after = deepcopy(before)
        after["tables"]["owned_rows"]["auto_increment_next"] = 50
        after["content_sha256"] = inventory.content_digest(after)
        self.assertFalse(inventory.compare(before, after))
        self.assertTrue(inventory.compare_schema(before, after))
        for invalid in (True, 0, -1, "50", 2 ** 64):
            after["tables"]["owned_rows"]["auto_increment_next"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError): inventory.validate_inventory(after)
        del after["tables"]["owned_rows"]["auto_increment_next"]
        with self.assertRaises(ValueError): inventory.validate_inventory(after)

    def test_schema_only_comparison_never_asserts_row_equality(self):
        before = fixture(); after = deepcopy(before)
        after["tables"]["owned_rows"]["rows_sha256"] = "c" * 64
        after["tables"]["owned_rows"]["row_count"] = 2
        after["content_sha256"] = inventory.content_digest(after)
        self.assertTrue(inventory.compare_schema(before, after))
        self.assertFalse(inventory.compare(before, after))


@unittest.skipUnless(os.environ.get("RUN_MYSQL_INVENTORY_TEST") == "true", "opt-in disposable MySQL test")
class MysqlInventoryRealTest(unittest.TestCase):
    def test_actual_mvcc_snapshot_is_read_only_and_detects_row_and_semantic_schema_changes(self):
        name = "flare-inventory-test-" + secrets.token_hex(6); container = None
        with tempfile.TemporaryDirectory(prefix="flare-inventory-owned-") as directory:
            env = Path(directory) / "mysql.env"
            env.write_text("MYSQL_ROOT_PASSWORD=" + secrets.token_hex(24) + "\nMYSQL_DATABASE=inventory_owned\n"); env.chmod(0o600)
            try:
                container = subprocess.run(["docker", "run", "-d", "--network", "none", "--name", name, "--env-file", str(env), IMAGE],
                                           capture_output=True, check=True).stdout.decode().strip()
                command = ["docker", "exec", "-i", container, "sh", "-ceu",
                           'export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; exec mysql -uroot --database="$MYSQL_DATABASE" --default-character-set=utf8mb4']
                def sql(value):
                    result = subprocess.run(command, input=value.encode(), capture_output=True)
                    if result.returncode:
                        codes = re.findall(rb"ERROR\s+\d{3,5}", result.stderr[:16384])
                        raise RuntimeError("owned disposable MySQL fixture failed: " +
                                           ",".join(code.decode() for code in codes))
                    return result
                for _ in range(60):
                    ready = subprocess.run(command, input=b"SELECT 1;", capture_output=True)
                    if ready.returncode == 0: break
                    time.sleep(1)
                else:
                    codes = re.findall(rb"ERROR\s+\d{3,5}", ready.stderr[:16384])
                    state = subprocess.run(["docker", "inspect", container, "--format", "{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}"],
                                           capture_output=True, text=True, check=False).stdout.strip()
                    self.fail("owned isolated MySQL did not become ready: " + state + "; exit=" + str(ready.returncode)
                              + "; " + ",".join(code.decode() for code in codes))
                sql("CREATE TABLE flyway_schema_history(installed_rank INT PRIMARY KEY,version VARCHAR(16),success BOOLEAN);"
                    "INSERT INTO flyway_schema_history VALUES(1,'32',1);"
                    "CREATE TABLE siem_ueba_model_jobs(model_version VARCHAR(96) PRIMARY KEY,feature_schema_version INT,data_provenance VARCHAR(16),status VARCHAR(16));"
                    "INSERT INTO siem_ueba_model_jobs VALUES('owned-model-fixture',3,'DEMO_ONLY','ACTIVE');"
                    "CREATE TABLE owned_rows(id INT AUTO_INCREMENT PRIMARY KEY,amount DECIMAL(12,4),payload VARBINARY(64),note VARCHAR(255),nullable_value VARCHAR(16) NULL);"
                    "INSERT INTO owned_rows(amount,payload,note,nullable_value) VALUES(1.1000,X'00FF','Tiếng Việt',NULL),(1.2000,X'0000','empty',''),(2.3000,X'FF00','last',NULL);")
                with inventory.MysqlReadOnly(container) as readonly:
                    initial = inventory.capture(readonly.query)
                    sql("UPDATE owned_rows SET amount=1.2000 WHERE id=1;")
                    same_snapshot = inventory.capture(readonly.query)
                self.assertTrue(inventory.compare(initial, same_snapshot))
                with inventory.MysqlReadOnly(container) as readonly: changed = inventory.capture(readonly.query)
                self.assertEqual(changed["tables"]["owned_rows"]["row_count"], initial["tables"]["owned_rows"]["row_count"])
                self.assertNotEqual(changed["tables"]["owned_rows"]["rows_sha256"], initial["tables"]["owned_rows"]["rows_sha256"])
                self.assertFalse(inventory.compare(initial, changed))
                with self.assertRaises(RuntimeError):
                    with inventory.MysqlReadOnly(container) as readonly: readonly.query("UPDATE owned_rows SET amount=99 WHERE id=1")
                with inventory.MysqlReadOnly(container) as readonly: unchanged = inventory.capture(readonly.query)
                self.assertTrue(inventory.compare(changed, unchanged))
                with inventory.MysqlReadOnly(container) as readonly:
                    quoted = inventory.capture(readonly.query)
                    readonly.query("SET SESSION sql_quote_show_create=0")
                    unquoted = inventory.capture(readonly.query)
                self.assertNotEqual(quoted["tables"]["owned_rows"]["raw_ddl_sha256"],
                                    unquoted["tables"]["owned_rows"]["raw_ddl_sha256"])
                self.assertTrue(inventory.compare(quoted, unquoted))
                sql("INSERT INTO owned_rows(amount,payload,note) VALUES(3.4000,X'01','counter advances');")
                with inventory.MysqlReadOnly(container) as readonly: inserted = inventory.capture(readonly.query)
                self.assertTrue(inventory.compare_schema(changed, inserted))
                self.assertNotEqual(changed["tables"]["owned_rows"]["raw_ddl_sha256"],
                                    inserted["tables"]["owned_rows"]["raw_ddl_sha256"])
                self.assertFalse(inventory.compare(changed, inserted))
                sql("ALTER TABLE owned_rows AUTO_INCREMENT=50;")
                with inventory.MysqlReadOnly(container) as readonly: counter_only = inventory.capture(readonly.query)
                self.assertEqual(counter_only["tables"]["owned_rows"]["auto_increment_next"], 50)
                self.assertEqual(inserted["tables"]["owned_rows"]["rows_sha256"],
                                 counter_only["tables"]["owned_rows"]["rows_sha256"])
                self.assertTrue(inventory.compare_schema(inserted, counter_only))
                self.assertFalse(inventory.compare(inserted, counter_only))
                sql("ALTER TABLE owned_rows MODIFY id INT NOT NULL;")
                with inventory.MysqlReadOnly(container) as readonly: no_auto = inventory.capture(readonly.query)
                self.assertIsNone(no_auto["tables"]["owned_rows"]["auto_increment_next"])
                self.assertFalse(inventory.compare_schema(counter_only, no_auto))
                sql("ALTER TABLE owned_rows ADD COLUMN extra_flag INT DEFAULT NULL;")
                with inventory.MysqlReadOnly(container) as readonly: altered = inventory.capture(readonly.query)
                self.assertFalse(inventory.compare_schema(inserted, altered))

                def semantics(table="semantic_rows", database="inventory_owned"):
                    with inventory.MysqlReadOnly(container) as readonly:
                        readonly.query("USE " + inventory.identifier(database))
                        return inventory.semantic_schema(readonly.query, table)

                def create_semantic_tables(database, *, explicit_charset=False):
                    charset = " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci" if explicit_charset else ""
                    sql("USE " + inventory.identifier(database) + ";"
                        "CREATE TABLE semantic_parent(id INT PRIMARY KEY) ENGINE=InnoDB;"
                        "CREATE TABLE semantic_rows(id INT PRIMARY KEY,parent_id INT,"
                        "label VARCHAR(32)" + charset + " DEFAULT 'alpha',score INT DEFAULT 1,"
                        "source_literal VARCHAR(64) DEFAULT 'inventory_owned',"
                        "INDEX label_idx(label),CONSTRAINT semantic_fk FOREIGN KEY(parent_id) REFERENCES semantic_parent(id) "
                        "ON UPDATE RESTRICT ON DELETE RESTRICT,CONSTRAINT semantic_check CHECK(score>=0)) "
                        "ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")

                create_semantic_tables("inventory_owned")
                baseline = semantics()
                with inventory.MysqlReadOnly(container) as readonly: baseline_inventory = inventory.capture(readonly.query)
                # Change actual MySQL metadata, not fabricated fingerprint fields.
                mutations = (
                    ("charset", "MODIFY label VARCHAR(32) CHARACTER SET latin1 COLLATE latin1_swedish_ci DEFAULT 'alpha'"),
                    ("collation", "MODIFY label VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT 'alpha'"),
                    ("default", "ALTER COLUMN label SET DEFAULT 'beta'"),
                    ("index", "DROP INDEX label_idx, ADD INDEX label_idx(label(8) DESC)"),
                    ("foreign_key", "DROP FOREIGN KEY semantic_fk; ALTER TABLE semantic_rows "
                                    "ADD CONSTRAINT semantic_fk FOREIGN KEY(parent_id) "
                                    "REFERENCES semantic_parent(id) ON UPDATE CASCADE ON DELETE CASCADE"),
                    ("check", "DROP CHECK semantic_check, ADD CONSTRAINT semantic_check CHECK(score>0)"),
                )
                for mutation, clause in mutations:
                    with self.subTest(real_metadata_change=mutation):
                        sql("ALTER TABLE semantic_rows " + clause + ";")
                        self.assertNotEqual(baseline, semantics())
                        with inventory.MysqlReadOnly(container) as readonly: drift = inventory.capture(readonly.query)
                        self.assertFalse(inventory.compare_schema(baseline_inventory, drift))
                        self.assertFalse(inventory.compare(baseline_inventory, drift))
                        self.assertNotEqual(drift["tables"]["semantic_rows"]["schema_sha256"],
                                            hashlib.sha256(inventory.canonical(baseline).encode()).hexdigest())
                        sql("DROP TABLE semantic_rows; DROP TABLE semantic_parent;")
                        create_semantic_tables("inventory_owned")
                        self.assertEqual(baseline, semantics())

                sql("CREATE DATABASE inventory_restore_owned;")
                create_semantic_tables("inventory_restore_owned", explicit_charset=True)
                self.assertEqual(baseline, semantics(database="inventory_restore_owned"))
                # Normalize actual self-schema reference fields only, never literals.
                sql("USE inventory_restore_owned; ALTER TABLE semantic_rows ALTER COLUMN source_literal "
                    "SET DEFAULT 'inventory_restore_owned';")
                self.assertNotEqual(baseline, semantics(database="inventory_restore_owned"))
                sql("CREATE DATABASE inventory_external_owned; CREATE DATABASE inventory_external_other;"
                    "CREATE TABLE inventory_external_owned.target(id INT PRIMARY KEY);"
                    "CREATE TABLE inventory_external_other.target(id INT PRIMARY KEY);")
                for database in ("inventory_owned", "inventory_restore_owned"):
                    sql("USE " + inventory.identifier(database) + ";CREATE TABLE semantic_external(id INT PRIMARY KEY,"
                        "target_id INT,CONSTRAINT external_fk FOREIGN KEY(target_id) "
                        "REFERENCES inventory_external_owned.target(id)) ENGINE=InnoDB;")
                external = semantics("semantic_external")
                self.assertEqual(external, semantics("semantic_external", "inventory_restore_owned"))
                sql("USE inventory_restore_owned; ALTER TABLE semantic_external DROP FOREIGN KEY external_fk;"
                    "ALTER TABLE semantic_external ADD CONSTRAINT external_fk FOREIGN KEY(target_id) "
                    "REFERENCES inventory_external_other.target(id);")
                self.assertNotEqual(external, semantics("semantic_external", "inventory_restore_owned"))
            finally:
                if container: subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


if __name__ == "__main__": unittest.main()
