#!/usr/bin/env python3
"""Private, consistent, read-only table/schema inventory for backup verification.

Credentials stay in the existing database container. No row values leave MySQL:
only sorted SHA-256 row hashes enter this process. Stored objects are refused
until their semantic restoration can also be checked; never silently omitted.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import time
import uuid

FORMAT = "MYSQL_ALL_TABLES_SHA256_V2"
LEGACY_FORMAT = "MYSQL_ALL_TABLES_SHA256_V1"
SCHEMA_FORMAT = "MYSQL_INFORMATION_SCHEMA_SEMANTICS_V1"
MAX_ROWS = 250000
MAX_OUTPUT = 32 * 1024 * 1024
HASH = re.compile(r"[a-f0-9]{64}")


def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", value):
        raise ValueError("unsupported database identifier")
    return "`" + value + "`"


class MysqlReadOnly:
    def __init__(self, container):
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{1,95}", container): raise ValueError("invalid owned container")
        self.errors = tempfile.TemporaryFile()
        command = ["docker", "exec", "-i", container, "sh", "-ceu",
                   'export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; exec mysql -uroot --database="$MYSQL_DATABASE" '
                   '--batch --raw --skip-column-names --unbuffered --default-character-set=utf8mb4']
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.errors)
        self.pending = bytearray()

    def query(self, sql):
        marker = ("INVENTORY_END_" + uuid.uuid4().hex).encode()
        self.process.stdin.write((sql.rstrip(";\n") + ";\nSELECT '" + marker.decode() + "';\n").encode())
        self.process.stdin.flush(); result = []; size = 0; deadline = time.monotonic() + 30
        while True:
            newline = self.pending.find(b"\n")
            if newline >= 0:
                line = bytes(self.pending[:newline]); del self.pending[:newline + 1]
                if line == marker: return b"\n".join(result)
                result.append(line); size += len(line) + 1
                if size > MAX_OUTPUT: raise ValueError("private inventory query exceeds output bound")
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise RuntimeError("read-only inventory query timed out")
            if not select.select([self.process.stdout], [], [], min(1, remaining))[0]: continue
            block = os.read(self.process.stdout.fileno(), 65536)
            if not block: raise RuntimeError("read-only MySQL inventory connection ended")
            self.pending.extend(block)
            if len(self.pending) > MAX_OUTPUT: raise ValueError("private inventory line exceeds bound")

    def __enter__(self):
        try:
            self.query("SET SESSION time_zone='+00:00'; SET SESSION information_schema_stats_expiry=0; "
                       "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ; "
                       "SET SESSION TRANSACTION READ ONLY; START TRANSACTION WITH CONSISTENT SNAPSHOT")
            return self
        except BaseException:
            self.__exit__(None, None, None); raise

    def __exit__(self, *_):
        try:
            if self.process.poll() is None:
                try: self.process.stdin.write(b"ROLLBACK;\nquit\n"); self.process.stdin.flush()
                except (BrokenPipeError, OSError): pass
            self.process.stdin.close()
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try: self.process.wait(timeout=3)
                except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(timeout=3)
        finally:
            self.process.stdout.close(); self.errors.close()


def rows_digest(hashes, expected_count):
    lines = hashes.splitlines() if hashes else []
    if len(lines) != expected_count or any(not HASH.fullmatch(value.decode("ascii")) for value in lines) or lines != sorted(lines):
        raise ValueError("row hashes do not conserve the actual sorted table population")
    digest = hashlib.sha256()
    for line in lines: digest.update(line + b"\n")
    return digest.hexdigest()


def content_digest(value):
    body = {key: value[key] for key in ("format", "schema_version", "tables", "primary_models", "stored_object_counts")}
    if value["format"] == FORMAT:
        # SHOW CREATE may render equivalent inherited/explicit charsets differently
        # across restore/server versions. It remains a private diagnostic, not a
        # substitute for the actual column/index/constraint semantics below.
        body["tables"] = {name: {key: table[key] for key in
                          ("columns", "row_count", "rows_sha256", "schema_sha256", "auto_increment_next")}
                          for name, table in value["tables"].items()}
        body["schema_fingerprint_format"] = value["schema_fingerprint_format"]
    return hashlib.sha256(canonical(body).encode()).hexdigest()


def semantic_schema(query, name):
    """Canonical non-statistical MySQL metadata; never rewrite expressions/DDL.

    Database names are normalized only for references to DATABASE() itself so
    importing the same schema into a differently named isolated database works.
    External references remain explicit. Metadata JSON stays inside this process;
    only its digest is written to the inventory.
    """
    identifier(name)
    condition = "TABLE_SCHEMA=DATABASE() AND TABLE_NAME='" + name + "'"

    def metadata(sql, width, *, minimum=0, maximum=4096):
        raw = query(sql)
        values = [json.loads(line) for line in raw.decode("utf-8").splitlines()] if raw else []
        if (not minimum <= len(values) <= maximum or
                any(not isinstance(row, list) or len(row) != width or
                    any(item is not None and type(item) not in (str, int) for item in row) for row in values)):
            raise ValueError("bounded semantic schema metadata required")
        return values

    # The next AUTO_INCREMENT value changes with rows, even when schema does not.
    # Column EXTRA still records whether auto-increment behavior is configured.
    properties = metadata("SELECT JSON_ARRAY(TABLE_TYPE,ENGINE,ROW_FORMAT,TABLE_COLLATION,CREATE_OPTIONS,"
                          "TABLE_COMMENT) FROM information_schema.TABLES WHERE " + condition,
                          6, minimum=1, maximum=1)
    columns = metadata("SELECT JSON_ARRAY(ORDINAL_POSITION,COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT,"
                       "EXTRA,GENERATION_EXPRESSION,CHARACTER_SET_NAME,COLLATION_NAME,COLUMN_COMMENT,SRS_ID) "
                       "FROM information_schema.COLUMNS WHERE " + condition + " ORDER BY ORDINAL_POSITION",
                       11, minimum=1, maximum=256)
    indexes = metadata("SELECT JSON_ARRAY(INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,COLLATION,SUB_PART,"
                       "PACKED,NULLABLE,INDEX_TYPE,COMMENT,INDEX_COMMENT,IS_VISIBLE,EXPRESSION) "
                       "FROM information_schema.STATISTICS WHERE " + condition + " ORDER BY INDEX_NAME,SEQ_IN_INDEX", 13)
    constraints = metadata("SELECT JSON_ARRAY(CONSTRAINT_NAME,CONSTRAINT_TYPE,ENFORCED) "
                           "FROM information_schema.TABLE_CONSTRAINTS WHERE " + condition + " ORDER BY CONSTRAINT_NAME", 3)
    keys = metadata("SELECT JSON_ARRAY(CONSTRAINT_NAME,ORDINAL_POSITION,COLUMN_NAME,POSITION_IN_UNIQUE_CONSTRAINT,"
                    "CASE WHEN REFERENCED_TABLE_SCHEMA=DATABASE() THEN '@SELF' ELSE REFERENCED_TABLE_SCHEMA END,"
                    "REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME) "
                    "FROM information_schema.KEY_COLUMN_USAGE WHERE " + condition +
                    " ORDER BY CONSTRAINT_NAME,ORDINAL_POSITION", 7)
    foreign_keys = metadata("SELECT JSON_ARRAY(CONSTRAINT_NAME,CASE WHEN UNIQUE_CONSTRAINT_SCHEMA=DATABASE() "
                            "THEN '@SELF' ELSE UNIQUE_CONSTRAINT_SCHEMA END,UNIQUE_CONSTRAINT_NAME,MATCH_OPTION,"
                            "UPDATE_RULE,DELETE_RULE,REFERENCED_TABLE_NAME) FROM information_schema.REFERENTIAL_CONSTRAINTS "
                            "WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='" + name + "' ORDER BY CONSTRAINT_NAME", 7)
    checks = metadata("SELECT JSON_ARRAY(c.CONSTRAINT_NAME,c.CHECK_CLAUSE) FROM information_schema.CHECK_CONSTRAINTS c "
                      "JOIN information_schema.TABLE_CONSTRAINTS t ON c.CONSTRAINT_SCHEMA=t.CONSTRAINT_SCHEMA "
                      "AND c.CONSTRAINT_NAME=t.CONSTRAINT_NAME WHERE t.TABLE_SCHEMA=DATABASE() AND t.TABLE_NAME='" + name +
                      "' AND t.CONSTRAINT_TYPE='CHECK' ORDER BY c.CONSTRAINT_NAME", 2)
    partitions = metadata("SELECT JSON_ARRAY(PARTITION_NAME,SUBPARTITION_NAME,PARTITION_ORDINAL_POSITION,"
                          "SUBPARTITION_ORDINAL_POSITION,PARTITION_METHOD,SUBPARTITION_METHOD,PARTITION_EXPRESSION,"
                          "SUBPARTITION_EXPRESSION,PARTITION_DESCRIPTION,PARTITION_COMMENT,NODEGROUP,TABLESPACE_NAME) "
                          "FROM information_schema.PARTITIONS WHERE " + condition +
                          " ORDER BY PARTITION_ORDINAL_POSITION,SUBPARTITION_ORDINAL_POSITION", 12, minimum=1)
    value = {"format": SCHEMA_FORMAT, "properties": properties, "columns": columns, "indexes": indexes,
             "constraints": constraints, "keys": keys, "foreign_keys": foreign_keys, "checks": checks,
             "partitions": partitions}
    if [row[1] for row in columns] != list(dict.fromkeys(row[1] for row in columns)):
        raise ValueError("semantic schema has duplicate columns")
    return value


def capture(query, *, schema_export_dir=None):
    if schema_export_dir is not None: schema_export_dir.mkdir(mode=0o700)
    objects = {}
    for name, table, field in (("views", "VIEWS", "TABLE_SCHEMA"), ("routines", "ROUTINES", "ROUTINE_SCHEMA"),
                               ("triggers", "TRIGGERS", "TRIGGER_SCHEMA"), ("events", "EVENTS", "EVENT_SCHEMA")):
        objects[name] = int(query(f"SELECT COUNT(*) FROM information_schema.{table} WHERE {field}=DATABASE()"))
    if any(objects.values()): raise ValueError("stored objects need a semantic verifier; table-only success is refused")
    names = query("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME").decode().splitlines()
    if not 1 <= len(names) <= 256 or len(set(names)) != len(names): raise ValueError("bounded unique table population required")
    tables = {}
    for name in names:
        quoted = identifier(name)
        columns = query("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='"
                        + name + "' ORDER BY ORDINAL_POSITION").decode().splitlines()
        if not 1 <= len(columns) <= 256 or len(set(columns)) != len(columns): raise ValueError("bounded unique columns required")
        expression = ",".join("HEX(CAST(" + identifier(column) + " AS BINARY))" for column in columns)
        count = int(query("SELECT COUNT(*) FROM " + quoted))
        if not 0 <= count <= MAX_ROWS: raise ValueError("actual inventory table exceeds row budget")
        hashes = query("SELECT SHA2(CAST(JSON_ARRAY(" + expression + ") AS CHAR),256) AS row_digest FROM " + quoted + " ORDER BY row_digest")
        definition = query("SHOW CREATE TABLE " + quoted)
        if schema_export_dir is not None:
            with (schema_export_dir / (name + '.sql')).open('xb') as output: output.write(definition)
            (schema_export_dir / (name + '.sql')).chmod(0o600)
        semantics = semantic_schema(query, name)
        if columns != [column[1] for column in semantics["columns"]]:
            raise ValueError("table column metadata changed during inventory capture")
        # Operational metadata is live rather than MVCC row state; do not use it
        # to assert structural drift on a mutable source database.
        next_id = json.loads(query("SELECT JSON_ARRAY(AUTO_INCREMENT) FROM information_schema.TABLES "
                                   "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='" + name + "'").decode())
        if (not isinstance(next_id, list) or len(next_id) != 1 or next_id[0] is not None and
                (type(next_id[0]) is not int or not 1 <= next_id[0] <= 2 ** 64 - 1)):
            raise ValueError("invalid auto-increment operational state")
        # InnoDB may retain an internal counter after AUTO_INCREMENT is removed.
        # That stale value is not a next-ID contract for a non-auto column.
        if not any("auto_increment" in (column[5] or "").split() for column in semantics["columns"]):
            next_id[0] = None
        tables[name] = {"columns": columns, "row_count": count, "rows_sha256": rows_digest(hashes, count),
                        "schema_sha256": hashlib.sha256(canonical(semantics).encode()).hexdigest(),
                        "raw_ddl_sha256": hashlib.sha256(definition).hexdigest(), "auto_increment_next": next_id[0]}
    schema = query("SELECT version FROM flyway_schema_history WHERE success=1 ORDER BY installed_rank DESC LIMIT 1").decode()
    # DB versions before V29 do not record the feature schema. Keep it NULL;
    # do not invent a model-schema claim from the database migration number.
    model_schema = "feature_schema_version" if "feature_schema_version" in tables["siem_ueba_model_jobs"]["columns"] else "NULL"
    primary = query("SELECT JSON_ARRAY(model_version," + model_schema + ",data_provenance) FROM siem_ueba_model_jobs WHERE status='ACTIVE' ORDER BY model_version").decode().splitlines()
    value = {"format": FORMAT, "schema_fingerprint_format": SCHEMA_FORMAT, "schema_version": schema,
             "tables": tables, "primary_models": [json.loads(line) for line in primary],
             "stored_object_counts": objects, "observed_at_utc": datetime.now(timezone.utc).isoformat()}
    value["content_sha256"] = content_digest(value); return value


def validate_inventory(value):
    if (not isinstance(value, dict) or value.get("format") not in (FORMAT, LEGACY_FORMAT) or not isinstance(value.get("schema_version"), str)
            or not re.fullmatch(r"[0-9]{1,4}", value["schema_version"])
            or not isinstance(value.get("tables"), dict) or not 1 <= len(value["tables"]) <= 256
            or value.get("stored_object_counts") != {"views": 0, "routines": 0, "triggers": 0, "events": 0}
            or not isinstance(value.get("primary_models"), list) or len(value["primary_models"]) > 2):
        raise ValueError("bounded all-table inventory required")
    if value["format"] == FORMAT and value.get("schema_fingerprint_format") != SCHEMA_FORMAT:
        raise ValueError("versioned semantic schema fingerprint required")
    for name, table in value["tables"].items():
        identifier(name)
        if (not isinstance(table, dict) or type(table.get("row_count")) is not int or not 0 <= table["row_count"] <= MAX_ROWS
                or not isinstance(table.get("columns"), list) or not 1 <= len(table["columns"]) <= 256
                or any(not isinstance(column, str) for column in table["columns"])
                or len(set(table["columns"])) != len(table["columns"])
                or any(not isinstance(table.get(key), str) or not HASH.fullmatch(table[key]) for key in ("schema_sha256", "rows_sha256"))):
            raise ValueError("invalid table/schema fingerprint")
        for column in table["columns"]: identifier(column)
        if value["format"] == FORMAT and (not isinstance(table.get("raw_ddl_sha256"), str) or
                                         not HASH.fullmatch(table["raw_ddl_sha256"])):
            raise ValueError("versioned raw DDL diagnostic fingerprint required")
        if value["format"] == FORMAT and ("auto_increment_next" not in table or table["auto_increment_next"] is not None and
                                         (type(table["auto_increment_next"]) is not int or
                                          not 1 <= table["auto_increment_next"] <= 2 ** 64 - 1)):
            raise ValueError("versioned auto-increment operational state required")
    for model in value["primary_models"]:
        if (not isinstance(model, list) or len(model) != 3 or not isinstance(model[0], str)
                or not re.fullmatch(r"[a-zA-Z0-9_-]{8,96}", model[0])
                or model[1] is not None and (type(model[1]) is not int or model[1] not in (1, 2, 3))
                or model[2] not in ("DEMO_ONLY", "REAL_ONLY", "MIXED", "UNKNOWN")):
            raise ValueError("invalid primary model binding")
    if value.get("content_sha256") != content_digest(value): raise ValueError("inventory content checksum changed")
    return value


def compare(expected, observed):
    validate_inventory(expected); validate_inventory(observed)
    if expected["format"] != observed["format"]:
        raise ValueError("different inventory formats cannot prove source equality; recapture without rewriting evidence")
    return expected["content_sha256"] == observed["content_sha256"]


def compare_schema(expected, observed):
    """All-table schema comparison, never mistaken for full row equality."""
    validate_inventory(expected); validate_inventory(observed)
    if expected["format"] != observed["format"]:
        raise ValueError("different schema fingerprint formats require new live captures")
    return (set(expected["tables"]) == set(observed["tables"]) and
            all(expected["tables"][name]["columns"] == observed["tables"][name]["columns"] and
                expected["tables"][name]["schema_sha256"] == observed["tables"][name]["schema_sha256"]
                for name in expected["tables"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--container", required=True)
    parser.add_argument("--output", type=Path); args = parser.parse_args(); os.umask(0o077)
    with MysqlReadOnly(args.container) as mysql: value = capture(mysql.query)
    validate_inventory(value); encoded = canonical(value)
    if args.output:
        with args.output.open("x") as stream: stream.write(encoded)
    else: print(encoded)


if __name__ == "__main__":
    try: main()
    except Exception as failure:
        raise SystemExit("Private read-only inventory failed: " + type(failure).__name__ + "; SQL, credentials and row data omitted") from None
