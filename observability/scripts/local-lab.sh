#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
RUNTIME_DIR="${ROOT_DIR}/observability/runtime"
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-flare-local-elk}
export OBSERVABILITY_ROOT_DIR="$ROOT_DIR"
export FILEBEAT_CERTS_DIR="${ROOT_DIR}/.secrets/observability/web"
export OBSERVABILITY_COMPOSE_ENV_FILE="${ROOT_DIR}/.env.e2e.example"
export OBSERVABILITY_COMPOSE_FILES="${ROOT_DIR}/docker-compose.yml:${ROOT_DIR}/docker-compose.e2e.yml:${ROOT_DIR}/observability/docker-compose.monitor.yml:${ROOT_DIR}/observability/docker-compose.local.yml"
compose_args=(--env-file "$OBSERVABILITY_COMPOSE_ENV_FILE" --project-name "$COMPOSE_PROJECT_NAME" --profile observability)
IFS=: read -r -a compose_files <<<"$OBSERVABILITY_COMPOSE_FILES"
for file in "${compose_files[@]}"; do compose_args+=(-f "$file"); done
compose() { docker compose "${compose_args[@]}" "$@"; }

capture_failure() {
  local status=$?
  [ "$status" -eq 0 ] && return
  install -d -m 0750 "$RUNTIME_DIR"
  compose ps --all >"${RUNTIME_DIR}/local-lab-ps.txt" 2>&1 || true
  compose logs --no-color --timestamps >"${RUNTIME_DIR}/local-lab-logs.txt" 2>&1 || true
  printf 'Local lab failed; containers, queues and volumes were preserved. Diagnostics: %s\n' "$RUNTIME_DIR" >&2
  exit "$status"
}
trap capture_failure ERR

bootstrap() { "${ROOT_DIR}/observability/scripts/bootstrap-secrets.sh"; }
validate() { "${ROOT_DIR}/observability/scripts/validate-config.sh"; }

up() {
  bootstrap
  compose up -d elasticsearch
  compose up --wait --wait-timeout 240 -d elasticsearch
  "${ROOT_DIR}/observability/scripts/setup-elastic.sh"
  compose up -d logstash kibana
  compose up --wait --wait-timeout 300 -d logstash kibana
  "${ROOT_DIR}/observability/scripts/setup-kibana.sh"
  compose build app
  compose build nginx
  compose up --wait --wait-timeout 300 -d db redis mailpit app nginx filebeat
  printf 'Flare local ELK is ready: Web http://127.0.0.1:%s, Kibana http://127.0.0.1:5601.\n' "${LOCAL_LAB_WEB_PORT:-8088}"
}

verify() { "${ROOT_DIR}/observability/scripts/verify-local-lab.sh"; }
evidence() { "${ROOT_DIR}/observability/scripts/create-evidence.sh"; }
down() { compose down --remove-orphans; }

purge() {
  [ "${LOCAL_LAB_PURGE_CONFIRM:-}" = yes ] || { printf 'Set LOCAL_LAB_PURGE_CONFIRM=yes to delete local volumes and observability secrets.\n' >&2; exit 1; }
  compose down --volumes --remove-orphans
  rm -rf "${ROOT_DIR}/.secrets/observability" "$RUNTIME_DIR"
  printf 'Local ELK volumes, runtime files and observability secrets were purged.\n'
}

all() {
  bootstrap
  validate
  up
  verify
  evidence
}

case "${1:-}" in
  bootstrap) bootstrap ;;
  validate) validate ;;
  up) up ;;
  verify) verify ;;
  evidence) evidence ;;
  down) down ;;
  purge) purge ;;
  all) all ;;
  *) printf 'Usage: %s {bootstrap|validate|up|verify|evidence|down|purge|all}\n' "$0" >&2; exit 2 ;;
esac
