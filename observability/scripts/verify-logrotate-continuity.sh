#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"

for binary in docker jq; do
  command -v "$binary" >/dev/null 2>&1 || { printf 'Missing required command: %s\n' "$binary" >&2; exit 1; }
done

project=${COMPOSE_PROJECT_NAME:-flare-local-elk}
result_file="${ROOT_DIR}/observability/runtime/logrotate-verification.json"
export OBSERVABILITY_ROOT_DIR="$ROOT_DIR"
export FILEBEAT_CERTS_DIR="${ROOT_DIR}/.secrets/observability/web"
compose_args=(--env-file "${ROOT_DIR}/.env.e2e.example" --project-name "$project" --profile observability
  -f "${ROOT_DIR}/docker-compose.yml" -f "${ROOT_DIR}/docker-compose.e2e.yml"
  -f "${ROOT_DIR}/observability/docker-compose.monitor.yml" -f "${ROOT_DIR}/observability/docker-compose.local.yml")
compose() { docker compose "${compose_args[@]}" "$@"; }

runner_image="${project}-logrotate-continuity"
runtime_dir=$(mktemp -d)
cleanup() {
  docker image rm "$runner_image" >/dev/null 2>&1 || true
  rm -rf "$runtime_dir"
}
trap cleanup EXIT

elastic_api() {
  local endpoint=$1
  # Password expansion belongs to the container.
  # shellcheck disable=SC2016
  compose exec -T elasticsearch bash -ceu '
    password=$(cat /run/flare-secrets/elasticsearch.password)
    curl --fail --silent --show-error --cacert /usr/share/elasticsearch/config/certs/ca.crt \
      --user "elastic:${password}" -H "Content-Type: application/json" --data-binary @- \
      "https://localhost:9200${1}"
  ' -- "$endpoint"
}

event() {
  jq -nc --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg trace "$1" \
    '{"@timestamp":$timestamp,"trace.id":$trace,"source.ip":"203.0.113.10","http.request.method":"GET","http.request.bytes":0,"http.response.status_code":200,"http.response.body.bytes":0,"url.path":"/logrotate-continuity","url.query":"","url.original":"/logrotate-continuity","user_agent.original":"Flare logrotate verifier","event.duration_seconds":0.001,"nginx.upstream.status_code":"200","nginx.upstream.response_time":"0.001"}'
}

trace_count() {
  jq -nc --arg trace "$1" '{query:{term:{"trace.id":$trace}}}' | elastic_api '/logs-nginx.access-lab/_count' | jq -r '.count'
}

wait_trace() {
  local trace=$1
  for _ in $(seq 1 30); do
    [ "$(trace_count "$trace" 2>/dev/null || printf 0)" -eq 1 ] && return 0
    sleep 1
  done
  return 1
}

nginx_volume=$(compose config --format json | jq -er '.volumes["nginx-logs"].name')
pre_trace="rotate-pre-$(date +%s)-$$"
post_trace="rotate-post-$(date +%s)-$$"

docker build --pull=false --tag "$runner_image" --file observability/tests/logrotate/Dockerfile . >/dev/null
mkdir -m 0777 "${runtime_dir}/state"

event "$pre_trace" | compose exec -T nginx sh -c 'tee -a /var/log/nginx/access.json.log >/dev/null'
wait_trace "$pre_trace" || { printf 'Pre-rotation event was not ingested exactly once.\n' >&2; exit 1; }

docker run --rm --name "${project}-logrotate-continuity" --network none \
  --user 0:0 \
  -e FAKE_DOCKER_LOG=/state/docker.calls \
  -v "${nginx_volume}:/opt/flare/nginx-logs" -v "${runtime_dir}/state:/state" \
  "$runner_image" --verbose --force --state /state/status /etc/nginx-access
grep -F -- 'kill -s USR1 nginx' "${runtime_dir}/state/docker.calls" >/dev/null
compose kill -s USR1 nginx >/dev/null

event "$post_trace" | compose exec -T nginx sh -c 'tee -a /var/log/nginx/access.json.log >/dev/null'

wait_trace "$post_trace" || { printf 'Post-rotation event was not ingested exactly once.\n' >&2; exit 1; }
sleep 3
[ "$(trace_count "$pre_trace")" -eq 1 ] || { printf 'Pre-rotation event was duplicated after rotation.\n' >&2; exit 1; }
[ "$(trace_count "$post_trace")" -eq 1 ] || { printf 'Post-rotation event was duplicated after rotation.\n' >&2; exit 1; }

docker run --rm --name "${project}-logrotate-stat" --network none --read-only --cap-drop ALL \
  --user 101:1000 --entrypoint sh -v "${nginx_volume}:/opt/flare/nginx-logs:ro" "$runner_image" -ceu '
    [ "$(stat -c "%u:%g %a" /opt/flare/nginx-logs/access.json.log)" = "101:1000 640" ]
  '

install -d -m 0750 "$(dirname "$result_file")"
jq -nc --arg pre "$pre_trace" --arg post "$post_trace" \
  '{passed:true,pre_rotation_trace:$pre,post_rotation_trace:$post}' >"$result_file"
printf 'Logrotate continuity passed: pre=%s post=%s, each ingested exactly once.\n' "$pre_trace" "$post_trace"
