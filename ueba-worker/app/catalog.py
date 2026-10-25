"""Checksum-bound numeric shards for offline and internal operator-owned jobs.

No executable artifacts, user-selected paths, raw requests, IPs or labels enter
the model input. A manifest is only a recipe; its counts are verified on read.
"""

from collections import Counter
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import re

from app.contract import FEATURE_NAMES_V2, FEATURE_SCHEMAS, feature_array
from app.policy import canonical
from app.strict_metrics import FAMILIES

MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_SHARD_BYTES = 8 * 1024 * 1024
MAX_SHARD_ROWS = 5000
COHORTS = {"READY", "UNSEEN_READY", "COLD"}
ROW_FIELDS = {"frame_id", "account_id", "window_start", "label", "family", "cohort",
              "baseline_established", "trusted_window_count", "features"}
SHARD_FIELDS = {"id", "path", "sha256", "records", "normal", "positive", "families", "cohorts", "from", "to"}


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def parse_json(data):
    return json.loads(data, object_pairs_hook=no_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON")))


def sha256(data): return hashlib.sha256(data).hexdigest()


def utc(value):
    if not isinstance(value, str) or len(value) > 40: raise ValueError("invalid UTC timestamp")
    try: parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError: raise ValueError("invalid UTC timestamp") from None
    if parsed.utcoffset() != timedelta(0) or parsed.minute % 15 or parsed.second or parsed.microsecond:
        raise ValueError("UTC quarter-hour timestamp required")
    return parsed


def row_stats(rows):
    return {"records": len(rows), "normal": sum(row["label"] == 0 for row in rows),
            "positive": sum(row["label"] == 1 for row in rows),
            "families": dict(sorted(Counter(row["family"] for row in rows).items())),
            "cohorts": dict(sorted(Counter(row["cohort"] for row in rows).items())),
            "from": min(row["window_start"] for row in rows), "to": max(row["window_start"] for row in rows)}


def validate_rows(rows, schema=2):
    if type(schema) is not int or schema not in (2, 3, 4): raise ValueError("unsupported sharded feature schema")
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_SHARD_ROWS:
        raise ValueError("numeric shard must contain 1..5000 rows")
    ids, episodes = set(), set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != ROW_FIELDS: raise ValueError("numeric row contract mismatch")
        if any(not isinstance(row[name], str) or not re.fullmatch(r"[a-z0-9_-]{8,128}" if name == "frame_id" else r"[a-z0-9_-]{8,64}", row[name])
               for name in ("frame_id", "account_id")):
            raise ValueError("invalid pseudonymous identity")
        at = utc(row["window_start"])
        if (type(row["label"]) is not int or row["label"] not in (0, 1)
                or not isinstance(row["family"], str) or row["family"] not in {"normal", *FAMILIES}
                or (row["label"] == 0) != (row["family"] == "normal")
                or not isinstance(row["cohort"], str) or row["cohort"] not in COHORTS or type(row["baseline_established"]) is not bool
                or row["baseline_established"] != (row["cohort"] != "COLD")
                or type(row["trusted_window_count"]) is not int or not 0 <= row["trusted_window_count"] <= 1344
                or (row["trusted_window_count"] >= 30) != row["baseline_established"]):
            raise ValueError("invalid label/family/actual baseline cohort")
        if (not isinstance(row["features"], list) or len(row["features"]) != len(FEATURE_SCHEMAS[schema])
                or any(type(value) not in (int, float) for value in row["features"])):
            raise ValueError("numeric feature vector required")
        personal_indexes = (8, 9, 10, 11, 12) if schema == 2 else (8, 9, 10, 11, 12, 20, 21)
        if row["cohort"] == "COLD" and any(row["features"][index] != 0 for index in personal_indexes):
            raise ValueError("cold-start must not fabricate personalized features")
        episode = (row["account_id"], at.strftime("%Y-%m-%dT%H"))
        if row["frame_id"] in ids or episode in episodes:
            raise ValueError("duplicate frame/account-hour episode")
        ids.add(row["frame_id"]); episodes.add(episode)
    feature_array([row["features"] for row in rows], MAX_SHARD_ROWS, schema)
    if any(row["features"][6] > 9 for row in rows):
        raise ValueError("route groups exceed the actual raw-v2 server vocabulary")
    return row_stats(rows)


class ShardedDataset:
    """Root is configured by an operator, never obtained from a public request."""

    def __init__(self, root: Path, *, expected_sha256: str | None = None):
        self.root = root.resolve(strict=True)
        data = self._read("manifest.json", MAX_MANIFEST_BYTES)
        self.sha256 = sha256(data)
        if expected_sha256 is not None and expected_sha256 != self.sha256:
            raise ValueError("dataset manifest binding mismatch")
        self.manifest = parse_json(data)
        document = self.manifest
        schema = document.get("feature_schema_version") if isinstance(document, dict) else None
        telemetry_contract = 3 if schema == 4 else 2
        if (not isinstance(document, dict)
                or type(document.get("catalog_schema_version")) is not int or document["catalog_schema_version"] != 2
                or type(document.get("telemetry_contract_version")) is not int or document["telemetry_contract_version"] != telemetry_contract
                or type(schema) is not int or schema not in (2, 3, 4)
                or document.get("feature_names") != list(FEATURE_SCHEMAS[schema]) or document.get("data_provenance") != "DEMO_ONLY"
                or document.get("stage") not in ("PILOT", "STRICT")
                or not isinstance(document.get("dataset_id"), str) or not re.fullmatch(r"[a-z0-9_-]{8,32}", document["dataset_id"])
                or not isinstance(document.get("splits"), dict) or not 1 <= len(document["splits"]) <= 20):
            raise ValueError("invalid strict numeric catalogue")
        paths, ids = set(), set()
        for name, split in document["splits"].items():
            if not re.fullmatch(r"[a-z0-9_-]{4,64}", name) or not isinstance(split, dict):
                raise ValueError("invalid split identity")
            self._check_split(split, paths, ids)

    def _read(self, relative, maximum):
        path = self.root / relative
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != self.root and self.root in parent.parents):
            raise ValueError("catalogue symlinks are not accepted")
        if path.resolve(strict=True).is_relative_to(self.root) is False or not path.is_file():
            raise ValueError("catalogue path escapes operator root")
        with path.open("rb") as stream: data = stream.read(maximum + 1)
        if len(data) > maximum: raise ValueError("catalogue file exceeds bound")
        return data

    @staticmethod
    def _check_split(split, paths, ids):
        expected_fields = {"records", "normal", "positive", "families", "cohorts", "from", "to", "shards", "sha256"}
        if set(split) != expected_fields or not isinstance(split["shards"], list) or not 1 <= len(split["shards"]) <= 10000:
            raise ValueError("bounded split descriptor required")
        if any(type(split[key]) is not int or split[key] < 0 for key in ("records", "normal", "positive")):
            raise ValueError("invalid split population")
        encoded = {key: value for key, value in split.items() if key != "sha256"}
        if sha256(canonical(encoded).encode()) != split["sha256"]: raise ValueError("split manifest checksum mismatch")
        totals = Counter(); families = Counter(); cohorts = Counter()
        for shard in split["shards"]:
            if (not isinstance(shard, dict) or set(shard) != SHARD_FIELDS
                    or not isinstance(shard["id"], str) or not re.fullmatch(r"[a-z0-9_-]{8,96}", shard["id"])
                    or shard["path"] != "shards/" + shard["id"] + ".json"
                    or not isinstance(shard["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", shard["sha256"])
                    or shard["path"] in paths or shard["id"] in ids):
                raise ValueError("invalid/duplicate shard identity or path")
            paths.add(shard["path"]); ids.add(shard["id"])
            if any(type(shard[key]) is not int or shard[key] < 0 for key in ("records", "normal", "positive")):
                raise ValueError("invalid shard population")
            if not 1 <= shard["records"] <= MAX_SHARD_ROWS or shard["normal"] + shard["positive"] != shard["records"]:
                raise ValueError("invalid shard population")
            for key, allowed, accumulator in (("families", {"normal", *FAMILIES}, families), ("cohorts", COHORTS, cohorts)):
                value = shard[key]
                if (not isinstance(value, dict) or not set(value) <= allowed
                        or any(type(count) is not int or count < 1 for count in value.values())
                        or sum(value.values()) != shard["records"]): raise ValueError("invalid shard groups")
                accumulator.update(value)
            if shard["families"].get("normal", 0) != shard["normal"]: raise ValueError("normal family/population mismatch")
            if utc(shard["from"]) > utc(shard["to"]): raise ValueError("invalid shard time range")
            totals.update({key: shard[key] for key in ("records", "normal", "positive")})
        expected = {**dict(totals), "families": dict(sorted(families.items())), "cohorts": dict(sorted(cohorts.items())),
                    "from": min(row["from"] for row in split["shards"]), "to": max(row["to"] for row in split["shards"])}
        if any(split.get(key) != value for key, value in expected.items()): raise ValueError("split counts/range differ from shard manifest")

    def split(self, name):
        try: return self.manifest["splits"][name]
        except KeyError: raise ValueError("unknown catalogue split") from None

    def load_shard(self, name, number):
        descriptor = self.split(name)["shards"][number]
        data = self._read(descriptor["path"], MAX_SHARD_BYTES)
        if sha256(data) != descriptor["sha256"]: raise ValueError("numeric shard checksum mismatch")
        rows = parse_json(data)
        stats = validate_rows(rows, self.manifest["feature_schema_version"])
        if any(descriptor[key] != value for key, value in stats.items()): raise ValueError("numeric rows differ from claimed shard statistics")
        if "fit" in name or "calibration" in name:
            if stats["positive"]: raise ValueError("abnormal label leaked into fitting/calibration")
        return descriptor, rows

    def iter_shards(self, name):
        for number in range(len(self.split(name)["shards"])): yield self.load_shard(name, number)
