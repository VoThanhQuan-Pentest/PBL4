"""Shared admission for destructive test cleanup and scanner setup: CI only."""
import os
from pathlib import Path
import re


def require_ci_scope():
    project = os.environ.get('COMPOSE_PROJECT_NAME', '')
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or not re.fullmatch(r'pbl4-observability-runtime-[0-9]+-[0-9]+', project)):
        raise RuntimeError('Only the disposable hosted ASVS project is authorized')
    workspace = Path(os.environ.get('GITHUB_WORKSPACE', '')).resolve()
    if workspace != Path(__file__).resolve().parents[2]:
        raise RuntimeError('ASVS workspace differs from the checked-out source')
    return project, workspace
