import subprocess
import contextlib
import importlib.util
import io
from datetime import datetime, timezone
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "seed-ueba-demo.py"
DUMMY_HASH = "{bcrypt-sha256}$2b$12$" + "A" * 53


class SeedUebaDemoContractTest(unittest.TestCase):
    def run_generator(self, mode, dataset="ueba-test"):
        args = [sys.executable, str(SCRIPT), mode, "--dataset-id", dataset,
                "--now", "2026-09-26T12:00:00Z"]
        if mode == "normal":
            args += ["--password-hash", DUMMY_HASH]
        return subprocess.run(args, check=False, capture_output=True, text=True)

    def test_normal_fixture_is_deterministic_and_separated_from_real_events(self):
        first = self.run_generator("normal")
        second = self.run_generator("normal")
        self.assertEqual(first.returncode, 0)
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.stdout.count("INSERT IGNORE INTO siem_security_events"), 2532)
        self.assertEqual(first.stdout.count("INSERT IGNORE INTO tbl_nguoi_dung"), 4)
        self.assertEqual(first.stdout.count("'NORMAL'"), 2532)
        self.assertNotIn("'ABNORMAL'", first.stdout)
        self.assertEqual(first.stdout.splitlines()[-1], "COMMIT;")

    def test_abnormal_fixture_is_idempotent_and_never_a_training_normal(self):
        result = self.run_generator("abnormal")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count("INSERT IGNORE INTO siem_security_events"), 136)
        self.assertEqual(result.stdout.count("'ABNORMAL'"), 136)
        self.assertNotIn("INSERT IGNORE INTO tbl_nguoi_dung", result.stdout)

    def test_dataset_id_cannot_inject_sql(self):
        result = self.run_generator("normal", "demo'; DROP TABLE users; --")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_aws_wrapper_can_assign_distinct_hashes_without_changing_local_cli(self):
        spec = importlib.util.spec_from_file_location('generator', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        hashes = ["{bcrypt-sha256}$2b$12$" + character * 53 for character in 'ABCD']
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            module.emit_normal('aws-test', hashes, datetime(2026, 9, 28, tzinfo=timezone.utc))
        for value in hashes:
            self.assertEqual(output.getvalue().count(value), 1)


if __name__ == "__main__":
    unittest.main()
