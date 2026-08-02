#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
RESULT_FILE="${ROOT_DIR}/observability/runtime/logrotate-verification.json"
WEB_URL=${FLARE_LAB_TARGET:-"http://127.0.0.1:${LOCAL_LAB_WEB_PORT:-8088}"}

[ -r "$RESULT_FILE" ] || { printf 'Run verify-logrotate-continuity.sh before the recovery check.\n' >&2; exit 1; }
old_trace=$(jq -er '.post_rotation_trace' "$RESULT_FILE")
project=${COMPOSE_PROJECT_NAME:-flare-local-elk}
export COMPOSE_PROJECT_NAME="$project"
export OBSERVABILITY_ROOT_DIR="$ROOT_DIR"
export FILEBEAT_CERTS_DIR="${ROOT_DIR}/.secrets/observability/web"
compose_args=(--env-file "${ROOT_DIR}/.env.e2e.example" --project-name "$project" --profile observability
  -f "${ROOT_DIR}/docker-compose.yml" -f "${ROOT_DIR}/docker-compose.e2e.yml"
  -f "${ROOT_DIR}/observability/docker-compose.monitor.yml" -f "${ROOT_DIR}/observability/docker-compose.local.yml")
compose() { docker compose "${compose_args[@]}" "$@"; }

trace_count() {
  local trace=$1
  # Password expansion belongs to the container.
  # shellcheck disable=SC2016
  jq -nc --arg trace "$trace" '{query:{term:{"trace.id":$trace}}}' | compose exec -T elasticsearch bash -ceu '
    password=$(cat /run/flare-secrets/elasticsearch.password)
    curl --fail --silent --show-error --cacert /usr/share/elasticsearch/config/certs/ca.crt \
      --user "elastic:${password}" -H "Content-Type: application/json" --data-binary @- \
      https://localhost:9200/logs-nginx.access-lab/_count
  ' | jq -r '.count'
}

wait_trace() {
  local trace=$1
  for _ in $(seq 1 30); do
    [ "$(trace_count "$trace" 2>/dev/null || printf 0)" -eq 1 ] && return 0
    sleep 1
  done
  return 1
}

"${ROOT_DIR}/observability/scripts/local-lab.sh" down
"${ROOT_DIR}/observability/scripts/local-lab.sh" up

[ "$(trace_count "$old_trace")" -eq 1 ] || { printf 'Pre-restart Elasticsearch document did not persist.\n' >&2; exit 1; }
headers=$(mktemp)
trap 'rm -f "$headers"' EXIT
curl --fail --silent --show-error -D "$headers" -o /dev/null "${WEB_URL}/api/health"
new_trace=$(awk 'BEGIN{IGNORECASE=1} /^X-Request-ID:/ {gsub("\r", "", $2); print $2}' "$headers" | tail -n 1)
[ -n "$new_trace" ] || { printf 'Recovery request lacks X-Request-ID.\n' >&2; exit 1; }
wait_trace "$new_trace" || { printf 'Fresh post-restart event was not ingested exactly once.\n' >&2; exit 1; }

printf 'Full-stack recovery passed: persisted=%s fresh=%s.\n' "$old_trace" "$new_trace"
