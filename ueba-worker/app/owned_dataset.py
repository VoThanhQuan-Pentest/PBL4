"""Explicit offline archive opt-in; the ordinary catalogue contract is unchanged.

Hashes must come from an operator's trusted checkpoint, never from a public
request or an automatically discovered sidecar. This factory does not register
recipes, open holdout rows, modify files, or retire any source data.
"""
from pathlib import Path

from app.catalog import ShardedDataset


def open_owned_dataset(directory: Path, *, expected_sha256: str | None = None,
                       expected_archive_sha256: str | None = None):
    if expected_archive_sha256 is None:
        return ShardedDataset(directory, expected_sha256=expected_sha256)
    if expected_sha256 is None:
        raise ValueError("archive use requires both explicitly trusted manifest and sidecar hashes")
    from app.archived_catalog import ArchivedShardedDataset
    return ArchivedShardedDataset(directory, expected_sha256=expected_sha256,
                                  expected_archive_sha256=expected_archive_sha256)
