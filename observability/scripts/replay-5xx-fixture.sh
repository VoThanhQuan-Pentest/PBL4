#!/usr/bin/env bash
set -Eeuo pipefail

[ "${LOCAL_FIXTURE_CONFIRM:-}" = "yes" ] || { printf 'Set LOCAL_FIXTURE_CONFIRM=yes to write synthetic local events.\n' >&2; exit 1; }
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
export OBSERVABILITY_ROOT_DIR="$ROOT_DIR"
export FILEBEAT_CERTS_DIR="${ROOT_DIR}/.secrets/observability/web"
args=(--env-file "${ROOT_DIR}/.env.e2e.example" --project-name flare-local-elk --profile observability
  -f "${ROOT_DIR}/docker-compose.yml" -f "${ROOT_DIR}/docker-compose.e2e.yml"
  -f "${ROOT_DIR}/observability/docker-compose.monitor.yml" -f "${ROOT_DIR}/observability/docker-compose.local.yml")

run_id=$(date +%s)
for count in $(seq 1 6); do
  timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  jq -nc --arg timestamp "$timestamp" --arg trace "fixture-5xx-${run_id}-${count}" \
    '{"@timestamp":$timestamp,"trace.id":$trace,"source.ip":"203.0.113.10","http.request.method":"GET","http.request.bytes":0,"http.response.status_code":503,"http.response.body.bytes":0,"url.path":"/fixture-5xx","url.query":"","url.original":"/fixture-5xx","user_agent.original":"Flare synthetic fixture","event.duration_seconds":0.001,"nginx.upstream.status_code":"503","nginx.upstream.response_time":"0.001"}' |
    docker compose "${args[@]}" exec -T nginx sh -c 'tee -a /var/log/nginx/access.json.log >/dev/null'
done

printf 'Six synthetic local 5xx events appended.\n'
