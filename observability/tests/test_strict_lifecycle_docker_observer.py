"""Private synthetic daemon only; never reads the actual Docker daemon/runtime."""
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socketserver
import tempfile
import threading
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

P = load("strict_private_proxy_test", "strict-lifecycle-docker-proxy.py")
D = load("strict_private_shim_test", "strict-lifecycle-docker-shim.py")


class SyntheticDaemonHandler(socketserver.StreamRequestHandler):
    def handle(self):
        method, path, _ = self.rfile.readline(4096).decode().split()
        while self.rfile.readline(4096) != b"\r\n": pass
        self.server.requests.append((method, path))
        body = json.dumps(self.server.documents[path]).encode()
        self.wfile.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)


class PrivateObserverTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup); self.base = Path(temporary.name)
        self.source = self.base / "source/standard"; self.source.mkdir(parents=True, mode=0o700); self.source.parent.chmod(0o700)
        self.identifier = "7" * 64; self.image = "sha256:" + "8" * 64
        self.proxy_sha = hashlib.sha256(Path(P.__file__).read_bytes()).hexdigest()
        self.source_sha = hashlib.sha256(str(self.source).encode()).hexdigest()
        self.inspect_path = "/containers/" + self.identifier + "/json"
        self.document = {"Id": self.identifier, "Image": self.image, "State": {"Status": "running", "Running": True, "Error": "SECRET-STATE"},
            "Config": {"Hostname": self.identifier[:12], "Labels": {P.LABEL: "metadata-only", "flare.strict.identity": "9" * 64, "password": "SECRET-LABEL"},
                "Cmd": ["python", "SECRET-CMD", "--dataset=" + str(self.source)], "Entrypoint": ["SECRET-ENTRYPOINT"],
                "Env": ["PASSWORD=SECRET-ENV", "TOKEN=SECRET-SOURCE-ENV:" + str(self.source)]},
            "Mounts": [{"Source": str(self.source.parent), "Destination": "/source", "Secret": "SECRET-MOUNT"}, {"Source": "/unrelated/SECRET-PATH"}],
            "HostConfig": {"Secret": "SECRET-HOST"}}
        self.daemon = socketserver.UnixStreamServer(str(self.base / "daemon.sock"), SyntheticDaemonHandler)
        self.daemon.requests = []; self.daemon.documents = {"/containers/json?all=1": [{"Id": self.identifier, "Names": ["SECRET-NAME"]}], self.inspect_path: self.document}
        daemon_thread = threading.Thread(target=self.daemon.serve_forever, daemon=True); daemon_thread.start()
        self.addCleanup(self.close_server, self.daemon, daemon_thread)
        self.proxy_path = self.base / "metadata.sock"
        self.proxy = P.ObserverServer(self.proxy_path, self.source, self.proxy_sha, daemon_socket=self.base / "daemon.sock")
        proxy_thread = threading.Thread(target=self.proxy.serve_forever, daemon=True); proxy_thread.start()
        self.addCleanup(self.close_server, self.proxy, proxy_thread)

    def close_server(self, server, thread):
        server.shutdown(); server.server_close(); thread.join(timeout=2)

    def observe(self, arguments, **changes):
        return D.observe(arguments, **{"socket_path": self.proxy_path, "proxy_sha": self.proxy_sha, "source_sha": self.source_sha, **changes})

    def request(self, method, path, *, body=None, headers=None):
        client = P.UnixHTTP(self.proxy_path)
        try:
            client.request(method, path, body=body, headers=headers or {"Connection": "close"})
            response = client.getresponse(); return response.status, response.read()
        finally: client.close()

    def test_exact_forms_produce_constructor_shapes_with_no_raw_secret_or_unrelated_path(self):
        inventory = self.observe(["container", "ls", "--all", "--quiet", "--no-trunc"])
        self.assertEqual(inventory, self.identifier + "\n")
        output = self.observe(["inspect", "--type", "container", self.identifier])
        value = json.loads(output)[0]
        self.assertEqual(set(value), {"Id", "Image", "State", "Config", "Mounts"})
        self.assertEqual(value["Config"]["Env"], [str(self.source)])
        self.assertEqual(value["Config"]["Cmd"], [str(self.source)])
        self.assertEqual(value["Config"]["Entrypoint"], [])
        self.assertEqual(value["Mounts"], [{"Source": str(self.source)}, {"Source": ""}])
        self.assertNotIn("SECRET", output); self.assertNotIn("PASSWORD", output); self.assertNotIn("TOKEN", output)
        self.assertEqual(self.daemon.requests, [("GET", "/containers/json?all=1"), ("GET", self.inspect_path)])
        self.assertEqual(self.proxy_path.stat().st_mode & 0o777, 0o600)

    def test_mutation_other_routes_queries_versions_and_request_bodies_never_reach_daemon(self):
        refused = [("POST", "/containers/create"), ("POST", self.inspect_path), ("DELETE", self.inspect_path),
            ("GET", "/containers/json"), ("GET", "/containers/json?all=0"), ("GET", "/v1.48/containers/json?all=1"),
            ("GET", "/containers/short/json"), ("GET", self.inspect_path + "?secret=SECRET"),
            ("GET", "/containers/" + self.identifier + "/start"), ("GET", "/info")]
        for method, path in refused:
            with self.subTest(method=method, path=path): self.assertEqual(self.request(method, path)[0], 403)
        self.assertEqual(self.request("GET", self.inspect_path, body=b"POST /exec SECRET")[0], 403)
        self.assertEqual(self.request("GET", self.inspect_path, headers={"Authorization": "Bearer SECRET"})[0], 403)
        self.assertEqual(self.daemon.requests, [])

    def test_shim_cannot_accept_general_docker_forms_or_adopt_short_ids(self):
        for arguments in (["run", "image"], ["start", self.identifier], ["exec", self.identifier, "sh"],
                          ["inspect", "--type", "container", self.identifier[:12]], ["container", "ls"],
                          ["inspect", "--type", "container", self.identifier, "--format", "SECRET"]):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(ValueError, "exact read-only"):
                self.observe(arguments)
        self.assertEqual(self.daemon.requests, [])

    def test_code_and_source_handshake_mismatch_refuse_without_output(self):
        for key in ("proxy_sha", "source_sha"):
            with self.subTest(pin=key), self.assertRaisesRegex(ValueError, "pinned bounded"):
                self.observe(["inspect", "--type", "container", self.identifier], **{key: "0" * 64})
        P.code_pin(P.__file__, self.proxy_sha)
        with self.assertRaisesRegex(ValueError, "pinned"): P.code_pin(P.__file__, "0" * 64)
        D.checked_code(hashlib.sha256(Path(D.__file__).read_bytes()).hexdigest())
        with self.assertRaisesRegex(ValueError, "immutable"): D.checked_code("0" * 64)

    def test_bad_upstream_shapes_duplicate_fields_and_caps_are_not_forwarded(self):
        original = self.daemon.documents[self.inspect_path]
        for value in ({**original, "Id": "0" * 64}, {**original, "Image": "SECRET"},
                      {**original, "State": {"Status": "SECRET", "Running": True}},
                      {**original, "Config": {**original["Config"], "Env": [123]}}):
            self.daemon.documents[self.inspect_path] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.observe(["inspect", "--type", "container", self.identifier])
        self.daemon.documents[self.inspect_path] = original
        with patch.object(P, "MAX_RESPONSE", 16), self.assertRaises(ValueError):
            self.observe(["inspect", "--type", "container", self.identifier])
        with self.assertRaises(ValueError): P.parse(b'{"Id":1,"Id":2}')
        with self.assertRaises(ValueError): D.parse(b'{"Id":1,"Id":2}')
        with patch.object(P, "MAX_CONTAINERS", 0), self.assertRaises(ValueError):
            self.observe(["container", "ls", "--all", "--quiet", "--no-trunc"])

    def test_same_uid_peer_check_private_socket_and_no_overwrite(self):
        with patch.object(P.struct, "unpack", return_value=(1, os.geteuid() + 1, 1)):
            self.assertEqual(self.request("GET", self.inspect_path)[0], 403)
        self.assertEqual(self.daemon.requests, [])
        with self.assertRaisesRegex(ValueError, "fresh"):
            P.ObserverServer(self.proxy_path, self.source, self.proxy_sha)
        self.proxy_path.chmod(0o666)
        with self.assertRaisesRegex(ValueError, "private"): self.observe(["inspect", "--type", "container", self.identifier])
        self.proxy_path.chmod(0o600)
        link = self.base / "linked.sock"; link.symlink_to(self.proxy_path)
        with self.assertRaisesRegex(ValueError, "canonical"): self.observe(["inspect", "--type", "container", self.identifier], socket_path=link)

    def test_deadline_sockets_bound_total_read_time_and_source_reference_symlinks(self):
        for module in (P, D):
            with module.DeadlineSocket() as connection:
                connection.deadline = 0
                with self.assertRaises(TimeoutError): connection.recv_into(bytearray(1))
        alias = self.base / "approved-alias"; alias.symlink_to(self.source.parent)
        self.assertTrue(P.source_mount(str(alias), self.source))
        self.assertFalse(P.source_mount("/unrelated/fixture", self.source))

    def test_helper_pins_refuse_mid_read_mode_change_symlinks_or_hardlinks(self):
        code = self.base / "code-fixture.py"; code.write_bytes(b"# Private inert code-pin fixture.\n"); code.chmod(0o644)
        expected = hashlib.sha256(code.read_bytes()).hexdigest()
        original = os.fstat; calls = 0
        def change_mode(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2: code.chmod(0o664)
            return original(descriptor)
        with patch.object(P.os, "fstat", side_effect=change_mode), self.assertRaisesRegex(ValueError, "immutable"):
            P.code_pin(code, expected)
        code.chmod(0o644); calls = 0
        with patch.object(D, "__file__", str(code)), patch.object(D.os, "fstat", side_effect=change_mode), self.assertRaisesRegex(ValueError, "immutable"):
            D.checked_code(expected)
        code.chmod(0o644); linked = self.base / "code-symlink.py"; linked.symlink_to(code)
        with self.assertRaisesRegex(ValueError, "symlink"): P.code_pin(linked, expected)
        hardlink = self.base / "code-hardlink.py"; os.link(code, hardlink)
        with self.assertRaisesRegex(ValueError, "immutable"): P.code_pin(code, expected)


if __name__ == "__main__": unittest.main()
