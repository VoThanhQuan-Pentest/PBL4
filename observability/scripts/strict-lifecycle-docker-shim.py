#!/usr/bin/env python3
"""Only the lifecycle constructor's exact two read-only Docker CLI forms."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import time

SHA = re.compile(r"[a-f0-9]{64}")
MAX_RESPONSE = 8 * 1024 * 1024
MAX_CONTAINERS = 1024
TIMEOUT = 10


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError("duplicate observation field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite observation")))


def checked_socket(path):
    path = Path(path).absolute()
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical private observation socket required")
    parent = path.parent.lstat(); value = path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700
            or not stat.S_ISSOCK(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o600):
        raise ValueError("owned private observation socket and directory required")
    return path, (value.st_dev, value.st_ino)


def checked_code(expected):
    if type(expected) is not str or SHA.fullmatch(expected) is None: raise ValueError("trusted shim SHA required")
    path = Path(__file__).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)): raise ValueError("shim code symlink refused")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        value = os.fstat(source.fileno()); body = source.read(1024 * 1024 + 1)
        signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid() or value.st_mode & 0o022
                or value.st_nlink != 1 or not 0 < value.st_size <= 1024 * 1024 or len(body) != value.st_size
                or signature(value) != signature(os.fstat(source.fileno())) or signature(value) != signature(path.lstat())
                or hashlib.sha256(body).hexdigest() != expected):
            raise ValueError("exact immutable Docker shim code required")


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, identity):
        super().__init__("localhost", timeout=TIMEOUT); self.path = path; self.identity = identity

    def connect(self):
        self.sock = DeadlineSocket(socket.AF_UNIX, socket.SOCK_STREAM); self.sock.settimeout(TIMEOUT)
        self.sock.connect(str(self.path))
        _, uid, _ = struct.unpack("3i", self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        if uid != os.geteuid() or (lambda value: (value.st_dev, value.st_ino))(self.path.lstat()) != self.identity:
            self.close(); raise ValueError("stable same-owner observation peer required")


class DeadlineSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs); self.deadline = time.monotonic() + TIMEOUT

    def recv_into(self, *args):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError("observation request deadline exceeded")
        self.settimeout(remaining)
        return super().recv_into(*args)


def observe(arguments, *, socket_path, proxy_sha, source_sha):
    if any(type(value) is not str or SHA.fullmatch(value) is None for value in (proxy_sha, source_sha)):
        raise ValueError("trusted proxy and exact source SHA required")
    if arguments == ["container", "ls", "--all", "--quiet", "--no-trunc"]:
        path = "/containers/json?all=1"; inventory = True
    elif len(arguments) == 4 and arguments[:3] == ["inspect", "--type", "container"] and SHA.fullmatch(arguments[3]):
        path = "/containers/" + arguments[3] + "/json"; inventory = False
    else: raise ValueError("only exact read-only lifecycle Docker forms permitted")
    path_socket, identity = checked_socket(socket_path); connection = UnixHTTP(path_socket, identity)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse(); length = response.getheader("Content-Length")
        if (response.status != 200 or response.getheader("X-Proxy-Code-Sha256") != proxy_sha
                or response.getheader("X-Proxy-Source-Sha256") != source_sha
                or length is None or not length.isdecimal() or not 0 < int(length) <= MAX_RESPONSE):
            raise ValueError("pinned bounded metadata-only observation required")
        body = response.read(MAX_RESPONSE + 1)
        if len(body) != int(length): raise ValueError("complete bounded observation required")
        value = parse(body)
    finally: connection.close()
    if checked_socket(path_socket)[1] != identity: raise ValueError("observation socket changed during request")
    if inventory:
        if (type(value) is not list or len(value) > MAX_CONTAINERS
                or any(type(item) is not dict or set(item) != {"Id"} or type(item["Id"]) is not str or SHA.fullmatch(item["Id"]) is None for item in value)):
            raise ValueError("exact filtered inventory required")
        ids = [item["Id"] for item in value]
        if len(set(ids)) != len(ids): raise ValueError("unique Docker inventory IDs required")
        return "".join(identifier + "\n" for identifier in ids)
    if type(value) is not dict or value.get("Id") != arguments[3]: raise ValueError("exact inspected observer ID required")
    return json.dumps([value], sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"


def main():
    try:
        checked_code(os.environ.get("UEBA_LIFECYCLE_DOCKER_SHIM_SHA256"))
        output = observe(sys.argv[1:], socket_path=os.environ["UEBA_LIFECYCLE_DOCKER_SOCKET"],
                         proxy_sha=os.environ["UEBA_LIFECYCLE_DOCKER_PROXY_SHA256"],
                         source_sha=os.environ["UEBA_LIFECYCLE_DOCKER_SOURCE_SHA256"])
        sys.stdout.write(output)
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        raise SystemExit("private Docker observation refused; only pinned read-only metadata forms supported") from None


if __name__ == "__main__": main()
