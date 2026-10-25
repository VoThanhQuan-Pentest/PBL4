"""Pre-allocation guard for owned offline work; never deletes or retries jobs."""
from pathlib import Path
import shutil

RESERVE_BYTES = 5_000_000_000


def require_headroom(directory: Path, planned_bytes: int = 0):
    if type(planned_bytes) is not int or not 0 <= planned_bytes <= 64 * 1024 ** 3:
        raise ValueError("bounded integer planned allocation required")
    free = shutil.disk_usage(directory).free
    if type(free) is not int or free < RESERVE_BYTES + planned_bytes:
        raise ValueError("insufficient storage headroom; preserve decimal5GB reserve before next allocation")
    return {"free_bytes": free, "planned_bytes": planned_bytes, "reserve_bytes": RESERVE_BYTES}
