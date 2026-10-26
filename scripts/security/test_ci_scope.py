import os
from pathlib import Path
import unittest
from unittest.mock import patch
from ci_scope import require_ci_scope


class HostedScopeTest(unittest.TestCase):
    def test_primary_project_and_nonhosted_execution_are_rejected(self):
        for env in [{'GITHUB_ACTIONS':'false'}, {'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'local'},
                    {'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','COMPOSE_PROJECT_NAME':'flare-otp-local'}]:
            with self.subTest(env=env), patch.dict(os.environ, env, clear=True), self.assertRaises(RuntimeError):
                require_ci_scope()

    def test_wrong_checkout_cannot_run_a_disposable_project(self):
        env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted',
             'COMPOSE_PROJECT_NAME':'pbl4-observability-runtime-123-1','GITHUB_WORKSPACE':'/nonexistent'}
        with patch.dict(os.environ, env, clear=True), self.assertRaises(RuntimeError): require_ci_scope()

    def test_only_the_hosted_project_bound_to_this_checkout_is_admitted(self):
        root=Path(__file__).resolve().parents[2]
        env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted',
             'COMPOSE_PROJECT_NAME':'pbl4-observability-runtime-123-1','GITHUB_WORKSPACE':str(root)}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(('pbl4-observability-runtime-123-1', root), require_ci_scope())


if __name__=='__main__': unittest.main()
