"""Offline contracts for the disposable local backup restore rehearsal."""
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "observability/scripts"
sys.path.insert(0, str(SCRIPTS))
import mysql_snapshot_inventory as inventory  # noqa: E402

SCRIPT = SCRIPTS / "rehearse-local-backup-restore.py"
SPEC = importlib.util.spec_from_file_location("local_backup_restore", SCRIPT)
restore = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = restore
SPEC.loader.exec_module(restore)


def inventory_fixture():
    value = {
        "format": inventory.FORMAT,
        "schema_fingerprint_format": inventory.SCHEMA_FORMAT,
        "schema_version": "36",
        "stored_object_counts": {"views": 0, "routines": 0, "triggers": 0, "events": 0},
        "primary_models": [],
        "tables": {"owned_rows": {"columns": ["id"], "row_count": 2,
                                   "rows_sha256": "a" * 64, "schema_sha256": "b" * 64,
                                   "raw_ddl_sha256": "c" * 64, "auto_increment_next": 3}},
    }
    value["content_sha256"] = inventory.content_digest(value)
    return value


class LocalBackupRestoreContractTest(unittest.TestCase):
    def test_sql_checkpoint_requires_expected_digest_and_complete_schema_dump(self):
        payload = b"CREATE TABLE flyway_schema_history(version VARCHAR(16));"
        compressed = gzip.compress(payload)
        digest = hashlib.sha256(compressed).hexdigest()
        self.assertEqual(restore.validate_sql_bytes(compressed, digest), (payload, digest))
        with self.assertRaisesRegex(restore.RehearsalError, "BACKUP_CHECKSUM_MISMATCH"):
            restore.validate_sql_bytes(compressed, "0" * 64)
        incomplete = gzip.compress(b"SELECT 1;")
        with self.assertRaisesRegex(restore.RehearsalError, "BACKUP_SQL_INCOMPLETE_OR_OVERSIZED"):
            restore.validate_sql_bytes(incomplete, hashlib.sha256(incomplete).hexdigest())
        invalid_gzip = b"not-a-gzip-stream"
        with self.assertRaisesRegex(restore.RehearsalError, "BACKUP_GZIP_INVALID"):
            restore.validate_sql_bytes(invalid_gzip, hashlib.sha256(invalid_gzip).hexdigest())

    def test_backup_source_label_is_explicit_and_never_misreports_aws_as_local(self):
        self.assertEqual(restore.source_metadata("LOCAL"),
                         {"scope": "LOCAL_CHECKPOINT_RESTORE", "source_environment": "LOCAL"})
        self.assertEqual(restore.source_metadata("AWS"),
                         {"scope": "AWS_BACKUP_DISPOSABLE_LOCAL_RESTORE", "source_environment": "AWS"})
        with self.assertRaisesRegex(restore.RehearsalError, "SOURCE_ENVIRONMENT_INVALID"):
            restore.source_metadata("UNKNOWN")

    def test_backup_path_requires_private_owned_file_inside_private_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "private-backups"
            root.mkdir(mode=0o700)
            checkpoint = root / "checkpoint"
            checkpoint.mkdir(mode=0o700)
            backup = checkpoint / "mysql.sql.gz"
            backup.write_bytes(gzip.compress(b"CREATE TABLE flyway_schema_history(version INT);"))
            backup.chmod(0o600)
            self.assertEqual(restore.private_regular_file(backup, root, 4096), backup)
            outside = Path(directory) / "outside.sql.gz"
            outside.write_bytes(backup.read_bytes())
            outside.chmod(0o600)
            with self.assertRaisesRegex(restore.RehearsalError, "PRIVATE_PATH_OUTSIDE_ROOT"):
                restore.private_regular_file(outside, root, 4096)
            link = checkpoint / "linked.sql.gz"
            link.symlink_to(backup)
            with self.assertRaisesRegex(restore.RehearsalError, "PRIVATE_PATH_SYMLINK_REJECTED"):
                restore.private_regular_file(link, root, 4096)

    def test_output_must_be_new_and_nested_in_owner_only_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "private-backups"
            root.mkdir(mode=0o700)
            checkpoint = root / "checkpoint"
            checkpoint.mkdir(mode=0o700)
            with patch.object(restore, "PRIVATE_ROOT", root):
                target = restore.private_output(checkpoint / "restore.json")
                self.assertEqual(target, checkpoint / "restore.json")
                with self.assertRaisesRegex(restore.RehearsalError, "OUTPUT_OUTSIDE_PRIVATE_ROOT"):
                    restore.private_output(Path(directory) / "outside.json")
                target.write_text("{}")
                with self.assertRaisesRegex(restore.RehearsalError, "OUTPUT_MUST_BE_NEW"):
                    restore.private_output(target)

    def test_container_command_is_bounded_offline_and_nonpublishing(self):
        command = restore.container_command("flare-local-restore-0123456789abcdef", "/private/mysql.env")
        self.assertIn("--rm", command)
        self.assertIn("--pull=never", command)
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertIn("1024m", command)
        self.assertIn("0.75", command)
        self.assertIn("--tmpfs", command)
        self.assertNotIn("-p", command)
        self.assertNotIn("--publish", command)
        self.assertNotIn("MYSQL_ROOT_PASSWORD", " ".join(command))
        with self.assertRaisesRegex(restore.RehearsalError, "CONTAINER_NAME_INVALID"):
            restore.container_command("arbitrary-user-container", "/private/mysql.env")

    def test_container_contract_rejects_network_ports_wrong_owner_and_unbounded_storage(self):
        safe = [{"HostConfig": {"NetworkMode": "none", "PortBindings": None,
                                "Memory": restore.MEMORY_BYTES,
                                "Tmpfs": {"/var/lib/mysql": "rw,noexec,nosuid,size=536870912"}},
                 "Config": {"Image": restore.MYSQL_IMAGE,
                            "Labels": {restore.CONTAINER_LABEL: restore.CONTAINER_SCOPE}},
                 "NetworkSettings": {"Networks": {"none": {}}},
                 "Mounts": [{"Type": "tmpfs"}]}]
        restore.validate_container(safe)
        mutations = (
            ("network", lambda item: item[0]["HostConfig"].update(NetworkMode="bridge")),
            ("port", lambda item: item[0]["HostConfig"].update(PortBindings={"3306/tcp": []})),
            ("label", lambda item: item[0]["Config"]["Labels"].clear()),
            ("memory", lambda item: item[0]["HostConfig"].update(Memory=0)),
            ("tmpfs", lambda item: item[0]["HostConfig"].update(Tmpfs={})),
            ("volume", lambda item: item[0].update(Mounts=[{"Type": "volume"}])),
        )
        for name, mutation in mutations:
            with self.subTest(name=name):
                changed = copy.deepcopy(safe)
                mutation(changed)
                with self.assertRaisesRegex(restore.RehearsalError, "CONTAINER_ISOLATION_CONTRACT_FAILED"):
                    restore.validate_container(changed)

    def test_inventory_summary_reports_counts_only_and_rejects_empty_or_invalid_inventory(self):
        value = inventory_fixture()
        summary = restore.inventory_summary(_JsonPath(value))
        self.assertEqual(summary["schema_version"], "36")
        self.assertEqual(summary["table_count"], 1)
        self.assertEqual(summary["row_count_total"], 2)
        self.assertNotIn("rows_sha256", json.dumps(summary))
        value["tables"]["owned_rows"]["row_count"] = 0
        value["content_sha256"] = inventory.content_digest(value)
        with self.assertRaisesRegex(restore.RehearsalError, "RESTORED_DATABASE_EMPTY"):
            restore.inventory_summary(_JsonPath(value))


class _JsonPath:
    def __init__(self, value):
        self.value = value

    def read_bytes(self):
        return json.dumps(self.value).encode()


if __name__ == "__main__":
    unittest.main()
