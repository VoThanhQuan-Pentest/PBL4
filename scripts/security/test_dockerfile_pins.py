"""Exercise the actual external-image pin guard across stage boundaries."""
from pathlib import Path
import subprocess
import tempfile
import unittest

RULE = Path(__file__).with_name('check_dockerfile_pins.awk')
PIN = 'alpine@sha256:' + 'a' * 64


class DockerfilePinsTest(unittest.TestCase):
    def check_files(self, *contents):
        with tempfile.TemporaryDirectory() as directory:
            files = []
            for index, text in enumerate(contents):
                file = Path(directory) / f'Dockerfile{index}'
                file.write_text(text)
                files.append(str(file))
            return subprocess.run(['awk', '-f', str(RULE), *files], capture_output=True, text=True)

    def test_pinned_external_and_earlier_named_stages_pass(self):
        result = self.check_files(f'FROM {PIN} AS base\nFROM base AS app\nFROM app\n')
        self.assertEqual(0, result.returncode, result.stdout)

    def test_stage_names_follow_docker_case_insensitivity(self):
        result = self.check_files(f'FROM {PIN} AS BASE\nfrom base as App\nFROM app\n')
        self.assertEqual(0, result.returncode, result.stdout)

    def test_unpinned_unknown_forward_and_self_references_fail(self):
        for text in ('FROM alpine:latest\n', 'FROM missing\n',
                     f'FROM later\nFROM {PIN} AS later\n', 'FROM same AS same\n',
                     f'FROM {PIN} AS base\nFROM base:latest\n',
                     'FROM alpine:latest AS base\nFROM base\n'):
            with self.subTest(text=text):
                result = self.check_files(text)
                self.assertNotEqual(0, result.returncode)
                self.assertIn('not digest pinned', result.stdout)

    def test_another_dockerfile_cannot_supply_a_stage_alias(self):
        result = self.check_files(f'FROM {PIN} AS base\n', 'FROM base\n')
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Dockerfile1:1:', result.stdout)


if __name__ == '__main__':
    unittest.main()
