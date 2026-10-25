#!/usr/bin/env python3
"""Private metadata-only Docker observation proxy; no general Docker API.

Only two fixed GET routes are admitted. The real daemon socket stays on the
host. Responses contain identity/status and sanitized source references only.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import stat
import struct
import time

ROOT = Path(__file__).resolve().parents[2]
DAEMON_SOCKET = Path("/var/run/docker.sock")
SHA = re.compile(r"[a-f0-9]{64}")
INSPECT = re.compile(r"/containers/([a-f0-9]{64})/json")
MAX_CONTAINERS = 1024
MAX_RESPONSE = 8 * 1024 * 1024
MAX_REQUEST = 4096
TIMEOUT = 10
STATES = {"created", "running", "paused", "restarting", "removing", "exited", "dead"}
LABEL = "flare.strict.lifecycle-observer"


def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError("duplicate observation field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite observation")))


def code_pin(path, expected):
    if type(expected) is not str or SHA.fullmatch(expected) is None: raise ValueError("trusted observer code SHA required")
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)): raise ValueError("observer code symlink refused")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno()); body = source.read(1024 * 1024 + 1)
        signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_mode, value.st_uid, value.st_nlink)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_mode & 0o022
                or before.st_nlink != 1 or not 0 < before.st_size <= 1024 * 1024 or len(body) != before.st_size
                or signature(before) != signature(os.fstat(source.fileno())) or signature(before) != signature(path.lstat())
                or hashlib.sha256(body).hexdigest() != expected):
            raise ValueError("pinned immutable observer code required")
    return expected


def private_directory(path):
    path = Path(path).absolute()
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("canonical private observer directory required")
    value = path.lstat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700:
        raise ValueError("owned 0700 observer directory required")
    return path


def approved_source(path):
    source = private_directory(path); parent = private_directory(source.parent); run = private_directory(parent.parent)
    if (source.name != "standard" or parent.name != "source" or run.parent != ROOT / "observability/runtime"
            or re.fullmatch(r"hybrid-strict-source-[A-Za-z0-9_-]{8,128}", run.name) is None):
        raise ValueError("exact explicit NEW source/standard observation binding required")
    return source


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=TIMEOUT); self.path = path

    def connect(self):
        self.sock = DeadlineSocket(socket.AF_UNIX, socket.SOCK_STREAM); self.sock.settimeout(TIMEOUT)
        self.sock.connect(str(self.path))


class DeadlineSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs); self.deadline = time.monotonic() + TIMEOUT

    def recv_into(self, *args):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError("observation request deadline exceeded")
        self.settimeout(remaining)
        return super().recv_into(*args)


def daemon_get(path, daemon_socket):
    named = Path(daemon_socket).stat()
    if not stat.S_ISSOCK(named.st_mode) or named.st_uid not in {0, os.geteuid()}:
        raise ValueError("trusted existing Docker socket required")
    identity = (named.st_dev, named.st_ino, named.st_uid, named.st_mode)
    connection = UnixHTTP(daemon_socket)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        _, uid, _ = struct.unpack("3i", connection.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        if uid != named.st_uid: raise ValueError("trusted Docker daemon peer required")
        response = connection.getresponse()
        length = response.getheader("Content-Length")
        if response.status != 200 or length is not None and (not length.isdecimal() or int(length) > MAX_RESPONSE):
            raise ValueError("bounded successful Docker observation required")
        body = response.read(MAX_RESPONSE + 1)
        if not 0 < len(body) <= MAX_RESPONSE: raise ValueError("bounded Docker observation required")
        current = Path(daemon_socket).stat()
        if (current.st_dev, current.st_ino, current.st_uid, current.st_mode) != identity:
            raise ValueError("Docker daemon socket changed during observation")
        return parse(body)
    finally: connection.close()


def source_mount(value, source):
    if type(value) is not str: raise ValueError("Docker mount source string required")
    if not value.startswith("/"): return False
    path = Path(value)
    if ".." in path.parts: raise ValueError("canonical Docker mount required")
    try: path = path.resolve()
    except (OSError, RuntimeError): raise ValueError("Docker mount unavailable") from None
    return path.is_relative_to(source.parent) or source.parent.is_relative_to(path)


def safe_arguments(values, source):
    if values is None: return []
    if type(values) is not list or len(values) > 4096 or any(type(value) is not str or len(value) > 65536 for value in values):
        raise ValueError("bounded Docker argument metadata required")
    # Preserve only the reference fact, never an assignment, secret or raw text.
    return [str(source) for value in values if str(source.parent) in value]


def filtered(path, value, source):
    if path == "/containers/json?all=1":
        if type(value) is not list or len(value) > MAX_CONTAINERS: raise ValueError("bounded Docker inventory required")
        ids = [item.get("Id") if type(item) is dict else None for item in value]
        if (any(type(identifier) is not str or SHA.fullmatch(identifier) is None for identifier in ids)
                or len(set(ids)) != len(ids)):
            raise ValueError("exact Docker inventory IDs required")
        return [{"Id": identifier} for identifier in ids]
    match = INSPECT.fullmatch(path)
    if (match is None or type(value) is not dict or value.get("Id") != match[1]
            or type(value.get("Image")) is not str or re.fullmatch(r"sha256:[a-f0-9]{64}", value["Image"]) is None):
        raise ValueError("exact inspected Docker identity required")
    state = value.get("State"); config = value.get("Config"); mounts = value.get("Mounts")
    if (type(state) is not dict or state.get("Status") not in STATES or type(state.get("Running")) is not bool
            or type(config) is not dict or type(config.get("Labels")) not in (dict, type(None))
            or type(mounts) is not list or len(mounts) > 4096):
        raise ValueError("bounded exact Docker runtime metadata required")
    labels = config.get("Labels") or {}; safe_labels = {}
    if labels.get(LABEL) == "metadata-only": safe_labels[LABEL] = "metadata-only"
    identity = labels.get("flare.strict.identity")
    if type(identity) is str and SHA.fullmatch(identity): safe_labels["flare.strict.identity"] = identity
    safe_mounts = []
    for mount in mounts:
        if type(mount) is not dict or type(mount.get("Source")) is not str: raise ValueError("complete Docker mounts required")
        safe_mounts.append({"Source": str(source) if source_mount(mount["Source"], source) else ""})
    return {"Id": value["Id"], "Image": value["Image"], "State": {"Status": state["Status"], "Running": state["Running"]},
        "Config": {"Hostname": value["Id"][:12] if config.get("Hostname") == value["Id"][:12] else "[REDACTED]",
            "Labels": safe_labels, **{key: safe_arguments(config.get(key), source) for key in ("Cmd", "Entrypoint", "Env")}},
        "Mounts": safe_mounts}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(TIMEOUT)
        status = 403; body = b'{"error":"observation refused"}'
        try:
            _, uid, _ = struct.unpack("3i", self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if uid != os.geteuid(): raise ValueError("same-owner private observer peer required")
            line = self.rfile.readline(MAX_REQUEST + 1)
            if len(line) > MAX_REQUEST or not line.endswith(b"\r\n"): raise ValueError("bounded observation request required")
            fields = line[:-2].split(b" ")
            if len(fields) != 3 or fields[0] != b"GET" or fields[2] != b"HTTP/1.1": raise ValueError("exact observation GET required")
            path = fields[1].decode("ascii")
            if path != "/containers/json?all=1" and INSPECT.fullmatch(path) is None: raise ValueError("observation route refused")
            total = len(line); headers = {}
            while True:
                line = self.rfile.readline(MAX_REQUEST + 1); total += len(line)
                if total > MAX_REQUEST or not line.endswith(b"\r\n"): raise ValueError("bounded observation headers required")
                if line == b"\r\n": break
                name, value = line[:-2].split(b":", 1); name = name.strip().lower()
                if name in headers or name not in {b"host", b"connection", b"accept", b"accept-encoding", b"content-length"}:
                    raise ValueError("unsupported observation header refused")
                headers[name] = value.strip()
            if b"content-length" in headers and headers[b"content-length"] != b"0": raise ValueError("observation bodies refused")
            code_pin(__file__, self.server.code_sha)
            body = canonical(filtered(path, daemon_get(path, self.server.daemon_socket), self.server.source))
            if len(body) > MAX_RESPONSE: raise ValueError("bounded filtered observation required")
            status = 200
        except (OSError, ValueError, TypeError, KeyError, UnicodeError, http.client.HTTPException):
            pass  # No raw upstream response, Docker environment or exception is returned.
        reason = "OK" if status == 200 else "Forbidden"
        self.wfile.write(f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\nX-Proxy-Code-Sha256: {self.server.code_sha}\r\nX-Proxy-Source-Sha256: {self.server.source_sha}\r\n\r\n".encode() + body)


class ObserverServer(socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 4

    def __init__(self, path, source, code_sha, *, daemon_socket=DAEMON_SOCKET):
        self.source = source; self.source_sha = hashlib.sha256(str(source).encode()).hexdigest()
        self.code_sha = code_sha; self.daemon_socket = daemon_socket
        path = Path(path).absolute(); private_directory(path.parent)
        if ".." in path.parts or path.exists() or path.is_symlink(): raise ValueError("fresh private observation socket required")
        old_mask = os.umask(0o177)
        try: super().__init__(str(path), Handler)
        finally: os.umask(old_mask)
        value = path.lstat()
        if not stat.S_ISSOCK(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o600:
            self.server_close(); raise ValueError("owned 0600 observation socket required")
        self.socket_identity = (value.st_dev, value.st_ino)

    def get_request(self):
        connection, address = super().get_request()
        return DeadlineSocket(fileno=connection.detach()), address

    def verify_request(self, request, address):
        try: value = Path(self.server_address).lstat()
        except OSError: return False
        return (stat.S_ISSOCK(value.st_mode) and stat.S_IMODE(value.st_mode) == 0o600 and value.st_uid == os.geteuid()
                and (value.st_dev, value.st_ino) == self.socket_identity)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True); parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--code-sha256", required=True)
    args = parser.parse_args()
    try:
        pin = code_pin(__file__, args.code_sha256); source = approved_source(args.source)
        daemon = DAEMON_SOCKET.stat()
        if not stat.S_ISSOCK(daemon.st_mode) or daemon.st_uid not in {0, os.geteuid()}:
            raise ValueError("existing trusted Docker daemon socket required")
        with ObserverServer(args.socket, source, pin) as server: server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass  # The private socket artifact is retained; never unlink/adopt it.
    except (OSError, ValueError):
        raise SystemExit("private Docker observation proxy refused; no daemon mutation; partial socket retained") from None


if __name__ == "__main__": main()
