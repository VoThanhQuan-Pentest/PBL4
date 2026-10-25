#!/usr/bin/env python3
"""Restore a private local or AWS MySQL checkpoint into a disposable isolated container.

This proves that the selected SQL archive can be imported and inventoried. It
does not claim equality with a live source captured at another time, does not
restore Kibana or UEBA files, and is not AWS EBS/production restore evidence.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
import zlib

from mysql_snapshot_inventory import FORMAT, validate_inventory

ROOT = Path(__file__).resolve().parents[2]
PRIVATE_ROOT = ROOT / "observability/runtime/private-backups"
INVENTORY_SCRIPT = ROOT / "observability/scripts/mysql_snapshot_inventory.py"
MYSQL_IMAGE = "mysql:8.4@sha256:c831a0f11348d402b43d77453e17d770be2eef356615a2823fe0f5a0d6c8b9af"
CONTAINER_LABEL = "flare.scope"
CONTAINER_SCOPE = "disposable-local-backup-restore"
MEMORY_BYTES = 1024 * 1024 * 1024
TMPFS_BYTES = 512 * 1024 * 1024
MAX_COMPRESSED_BYTES = 16 * 1024 * 1024
MAX_SQL_BYTES = 128 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}")
CONTAINER_RE = re.compile(r"flare-local-restore-[0-9a-f]{16}")


class RehearsalError(ValueError):
    """Safe failure code; never includes SQL, credentials, or subprocess output."""


def private_path(path, private_root):
    private_root = Path(private_root).absolute()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if ".." in candidate.parts or private_root.is_symlink() or not private_root.is_dir():
        raise RehearsalError("PRIVATE_PATH_INVALID")
    try:
        relative = candidate.relative_to(private_root)
    except ValueError:
        raise RehearsalError("PRIVATE_PATH_OUTSIDE_ROOT") from None
    if not relative.parts:
        raise RehearsalError("PRIVATE_PATH_INVALID")
    current = private_root
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise RehearsalError("PRIVATE_PATH_SYMLINK_REJECTED")
    try:
        resolved_root = private_root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError):
        raise RehearsalError("PRIVATE_PATH_INVALID") from None
    if resolved_root.stat().st_uid != os.getuid() or resolved_root.stat().st_mode & 0o077:
        raise RehearsalError("PRIVATE_ROOT_NOT_PRIVATE")
    parent = resolved if resolved.is_dir() else resolved.parent
    while True:
        metadata = parent.stat()
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise RehearsalError("PRIVATE_PARENT_NOT_PRIVATE")
        if parent == resolved_root:
            break
        try:
            parent.relative_to(resolved_root)
        except ValueError:
            raise RehearsalError("PRIVATE_PATH_INVALID") from None
        parent = parent.parent
    return resolved, resolved_root


def run(command, *, data=None, check=True, timeout=30):
    try:
        result = subprocess.run(command, input=data, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        raise RehearsalError("LOCAL_TOOL_FAILURE") from None
    if check and result.returncode:
        raise RehearsalError("LOCAL_TOOL_FAILURE")
    return result


def private_regular_file(path, private_root, maximum):
    path, _ = private_path(path, private_root)
    if not path.exists() or not path.is_file():
        raise RehearsalError("BACKUP_NOT_REGULAR")
    metadata = path.stat()
    if (metadata.st_uid != os.getuid() or metadata.st_nlink != 1
            or metadata.st_mode & 0o077 or metadata.st_size > maximum):
        raise RehearsalError("BACKUP_PERMISSIONS_OR_SIZE_INVALID")
    return path


def validate_sql_bytes(compressed, expected_sha256):
    if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
        raise RehearsalError("EXPECTED_SHA256_REQUIRED")
    actual_sha256 = hashlib.sha256(compressed).hexdigest()
    if actual_sha256 != expected_sha256:
        raise RehearsalError("BACKUP_CHECKSUM_MISMATCH")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as stream:
            payload = stream.read(MAX_SQL_BYTES + 1)
    except (OSError, EOFError, zlib.error):
        raise RehearsalError("BACKUP_GZIP_INVALID") from None
    if (len(payload) > MAX_SQL_BYTES or b"CREATE TABLE" not in payload
            or b"flyway_schema_history" not in payload):
        raise RehearsalError("BACKUP_SQL_INCOMPLETE_OR_OVERSIZED")
    return payload, actual_sha256


def container_command(name, env_file):
    if not isinstance(name, str) or not CONTAINER_RE.fullmatch(name):
        raise RehearsalError("CONTAINER_NAME_INVALID")
    return ["docker", "run", "--rm", "-d", "--pull=never", "--network", "none",
            "--name", name, "--label", f"{CONTAINER_LABEL}={CONTAINER_SCOPE}",
            "--memory", "1024m", "--memory-swap", "1024m", "--cpus", "0.75",
            "--tmpfs", f"/var/lib/mysql:rw,noexec,nosuid,size={TMPFS_BYTES},mode=0700",
            "--env-file", str(env_file), MYSQL_IMAGE, "--local-infile=0",
            "--secure-file-priv=NULL"]


def validate_container(inspected):
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
        raise RehearsalError("CONTAINER_IDENTITY_INVALID")
    value = inspected[0]
    host = value.get("HostConfig", {})
    config = value.get("Config", {})
    networking = value.get("NetworkSettings", {})
    networks = networking.get("Networks", {})
    if (host.get("NetworkMode") != "none" or host.get("PortBindings") not in (None, {})
            or set(networks) not in (set(), {"none"})
            or config.get("Labels", {}).get(CONTAINER_LABEL) != CONTAINER_SCOPE
            or config.get("Image") != MYSQL_IMAGE or host.get("Memory") != MEMORY_BYTES
            or not isinstance(host.get("Tmpfs"), dict)
            or "/var/lib/mysql" not in host["Tmpfs"]
            or any(mount.get("Type") != "tmpfs" for mount in value.get("Mounts", []))):
        raise RehearsalError("CONTAINER_ISOLATION_CONTRACT_FAILED")


def private_output(path):
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path
    if path.exists() or path.is_symlink():
        raise RehearsalError("OUTPUT_MUST_BE_NEW")
    try:
        _, private_root = private_path(path.parent, PRIVATE_ROOT)
    except RehearsalError as error:
        if str(error) == "PRIVATE_PATH_OUTSIDE_ROOT":
            raise RehearsalError("OUTPUT_OUTSIDE_PRIVATE_ROOT") from None
        raise
    parent = path.parent.resolve(strict=True)
    if parent == private_root or (parent.stat().st_uid != os.getuid()
                                  or (parent.stat().st_mode & 0o777) != 0o700):
        raise RehearsalError("OUTPUT_DIRECTORY_NOT_PRIVATE")
    return parent / path.name


def wait_for_mysql(name):
    command = ["docker", "exec", name, "sh", "-ceu",
               'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --local-infile=0 -uroot '
               '"$MYSQL_DATABASE" -e "SELECT 1"']
    for _ in range(60):
        if run(command, check=False, timeout=10).returncode == 0:
            return
        inspected = run(["docker", "inspect", name], check=False, timeout=10)
        if inspected.returncode == 0:
            try:
                state = json.loads(inspected.stdout)[0]["State"]
            except (IndexError, KeyError, json.JSONDecodeError):
                raise RehearsalError("DISPOSABLE_MYSQL_STATE_INVALID") from None
            if state.get("OOMKilled") is True:
                raise RehearsalError("DISPOSABLE_MYSQL_OOM")
            if state.get("Status") == "exited":
                raise RehearsalError("DISPOSABLE_MYSQL_EXITED")
        time.sleep(1)
    raise RehearsalError("DISPOSABLE_MYSQL_NOT_READY")


def inventory_summary(path):
    try:
        inventory = json.loads(path.read_bytes())
        validate_inventory(inventory)
    except (OSError, json.JSONDecodeError, ValueError):
        raise RehearsalError("RESTORED_INVENTORY_INVALID") from None
    if inventory.get("format") != FORMAT:
        raise RehearsalError("RESTORED_INVENTORY_FORMAT_UNSUPPORTED")
    rows = sum(table["row_count"] for table in inventory["tables"].values())
    if not rows:
        raise RehearsalError("RESTORED_DATABASE_EMPTY")
    return {"schema_version": inventory["schema_version"],
            "table_count": len(inventory["tables"]), "row_count_total": rows,
            "inventory_sha256": inventory["content_sha256"]}


def stop_owned_container(name):
    """Stop only the random, label-verified --rm container created by this run."""
    inspected = run(["docker", "inspect", name], check=False, timeout=10)
    if inspected.returncode:
        listing = run(["docker", "ps", "-a", "--format", "{{.Names}}"], check=False, timeout=10)
        return listing.returncode == 0 and name not in listing.stdout.decode("utf-8", "replace").splitlines()
    try:
        value = json.loads(inspected.stdout)[0]
    except (IndexError, json.JSONDecodeError):
        return False
    if value.get("Config", {}).get("Labels", {}).get(CONTAINER_LABEL) != CONTAINER_SCOPE:
        return False
    stopped = run(["docker", "stop", "--time", "5", name], check=False, timeout=15)
    if stopped.returncode:
        return False
    for _ in range(30):
        listing = run(["docker", "ps", "-a", "--format", "{{.Names}}"], check=False, timeout=5)
        if listing.returncode == 0 and name not in listing.stdout.decode("utf-8", "replace").splitlines():
            return True
        time.sleep(0.1)
    return False


def source_metadata(source_environment):
    if source_environment == "LOCAL":
        return {"scope": "LOCAL_CHECKPOINT_RESTORE", "source_environment": "LOCAL"}
    if source_environment == "AWS":
        return {"scope": "AWS_BACKUP_DISPOSABLE_LOCAL_RESTORE", "source_environment": "AWS"}
    raise RehearsalError("SOURCE_ENVIRONMENT_INVALID")


def rehearse(backup, expected_sha256, output, source_environment="LOCAL"):
    compressed = private_regular_file(backup, PRIVATE_ROOT, MAX_COMPRESSED_BYTES).read_bytes()
    payload, backup_sha256 = validate_sql_bytes(compressed, expected_sha256)
    source = source_metadata(source_environment)
    output = private_output(output)
    name = "flare-local-restore-" + secrets.token_hex(8)
    if run(["docker", "inspect", name], check=False).returncode == 0:
        raise RehearsalError("RANDOM_CONTAINER_NAME_COLLISION")
    evidence = {"passed": False, **source, "target_environment": "DISPOSABLE_LOCAL",
                "backup_sha256": backup_sha256, "mysql_image": MYSQL_IMAGE,
                "container_network": "none", "published_ports": False,
                "storage": "tmpfs", "original_local_database_modified": False,
                "aws_changed": False, "restore_container_removed": False}
    container_attempted = False
    failure_code = None
    summary = None
    stage = "PREPARE_DISPOSABLE_MYSQL"
    with tempfile.TemporaryDirectory(prefix="flare-local-restore-", dir=PRIVATE_ROOT) as temporary:
        env_file = Path(temporary) / "mysql.env"
        env_file.write_text("MYSQL_ROOT_PASSWORD=" + secrets.token_hex(32)
                            + "\nMYSQL_DATABASE=flare_restore\n")
        env_file.chmod(0o600)
        try:
            container_attempted = True
            run(container_command(name, env_file), timeout=60)
            stage = "VERIFY_CONTAINER_ISOLATION"
            inspected = json.loads(run(["docker", "inspect", name], timeout=10).stdout)
            validate_container(inspected)
            stage = "WAIT_FOR_DISPOSABLE_MYSQL"
            wait_for_mysql(name)
            stage = "IMPORT_BACKUP"
            import_command = ["docker", "exec", "-i", name, "sh", "-ceu",
                              'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --local-infile=0 '
                              '--default-character-set=utf8mb4 -uroot "$MYSQL_DATABASE"']
            run(import_command, data=payload, timeout=180)
            stage = "CAPTURE_RESTORED_INVENTORY"
            inventory_path = Path(temporary) / "restored-inventory.json"
            run([sys.executable, str(INVENTORY_SCRIPT), "--container", name,
                 "--output", str(inventory_path)], timeout=300)
            summary = inventory_summary(inventory_path)
            stage = "CLEANUP_DISPOSABLE_MYSQL"
        except (RehearsalError, subprocess.SubprocessError, OSError, json.JSONDecodeError) as error:
            failure_code = str(error) if isinstance(error, RehearsalError) else "RESTORE_OR_INVENTORY_FAILED"
        finally:
            removed = stop_owned_container(name) if container_attempted else True
            evidence["restore_container_removed"] = removed
            if not removed:
                stage = "CLEANUP_DISPOSABLE_MYSQL"
                failure_code = "DISPOSABLE_CONTAINER_CLEANUP_FAILED"
            evidence["observed_at"] = datetime.now(timezone.utc).isoformat()
            evidence["stage"] = stage
            evidence["passed"] = failure_code is None and summary is not None and removed
            evidence["failure_code"] = failure_code
            if summary is not None:
                evidence.update(summary)
            try:
                with output.open("x") as stream:
                    json.dump(evidence, stream, indent=2)
                output.chmod(0o600)
            except OSError:
                raise RehearsalError("PRIVATE_EVIDENCE_WRITE_FAILED") from None
    return output, evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", type=Path, required=True,
                        help="mode-0600 gzip SQL checkpoint under observability/runtime/private-backups")
    parser.add_argument("--expected-backup-sha256", required=True,
                        help="lowercase SHA-256 from the checkpoint SHA256SUMS file")
    parser.add_argument("--source-environment", choices=("LOCAL", "AWS"), default="LOCAL",
                        help="origin of the private SQL snapshot; target remains a disposable local container")
    parser.add_argument("--output", type=Path, required=True,
                        help="new evidence JSON in an existing private 0700 directory under private-backups")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        output, evidence = rehearse(args.backup, args.expected_backup_sha256, args.output,
                                    args.source_environment)
    except RehearsalError as error:
        print(json.dumps({"passed": False, "failure_code": str(error)}))
        return 1
    result = {key: evidence.get(key) for key in (
        "passed", "scope", "source_environment", "target_environment", "schema_version",
        "table_count", "row_count_total", "container_network", "published_ports",
        "original_local_database_modified", "aws_changed", "restore_container_removed")}
    result["private_evidence"] = str(output.relative_to(ROOT))
    print(json.dumps(result))
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
