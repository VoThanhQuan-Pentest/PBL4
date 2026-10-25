#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
RUNTIME_DIR="${ROOT_DIR}/observability/runtime"
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-flare-local-elk}
export OBSERVABILITY_ROOT_DIR="$ROOT_DIR"
UEBA_OPERATOR_GID=$(id -g)
export UEBA_OPERATOR_GID
export FILEBEAT_CERTS_DIR="${ROOT_DIR}/.secrets/observability/web"
export KIBANA_URL=${KIBANA_URL:-"http://127.0.0.1:${LOCAL_LAB_KIBANA_PORT:-5601}"}
export OBSERVABILITY_COMPOSE_ENV_FILE="${ROOT_DIR}/.env.e2e.example"
export OBSERVABILITY_COMPOSE_FILES=${OBSERVABILITY_COMPOSE_FILES:-"${ROOT_DIR}/docker-compose.yml:${ROOT_DIR}/docker-compose.e2e.yml:${ROOT_DIR}/observability/docker-compose.monitor.yml:${ROOT_DIR}/observability/docker-compose.local.yml"}
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

bootstrap() {
  "${ROOT_DIR}/observability/scripts/bootstrap-secrets.sh"
  "${ROOT_DIR}/observability/scripts/bootstrap-ueba.sh"
  "${ROOT_DIR}/observability/scripts/bootstrap-prevention.sh"
}
validate() { "${ROOT_DIR}/observability/scripts/validate-config.sh"; }

up() {
  bootstrap
  compose up -d elasticsearch
  compose up --wait --wait-timeout 240 -d elasticsearch
  "${ROOT_DIR}/observability/scripts/setup-elastic.sh"
  compose up -d logstash kibana
  compose up --wait --wait-timeout 300 -d logstash kibana
  "${ROOT_DIR}/observability/scripts/backup-kibana-before-import.sh"
  "${ROOT_DIR}/observability/scripts/setup-kibana.sh"
  compose build app
  compose build nginx
  compose build ueba-worker
  compose build gateway
  compose up --wait --wait-timeout 180 -d ueba-worker
  compose up --wait --wait-timeout 300 -d db redis mailpit app nginx filebeat
  # Filebeat inputs and Logstash pipeline bind mounts are not tracked by Compose
  # hashes; recreate them after config changes while preserving their volumes.
  compose up --wait --wait-timeout 180 --force-recreate --no-deps -d logstash filebeat
  compose up --wait --wait-timeout 180 -d gateway
  printf 'Flare local ELK is ready: Web http://127.0.0.1:%s, Kibana http://127.0.0.1:%s.\n' "${LOCAL_LAB_WEB_PORT:-8088}" "${LOCAL_LAB_KIBANA_PORT:-5601}"
}

verify() { "${ROOT_DIR}/observability/scripts/verify-local-lab.sh"; }
evidence() { "${ROOT_DIR}/observability/scripts/create-evidence.sh"; }
down() { compose down --remove-orphans; }

seed_ueba_demo() {
  local mode=$1 dataset=${UEBA_DEMO_DATASET_ID:-"ueba-$(date -u +%Y%m%d)"}
  [ "${UEBA_DEMO_CONFIRM:-}" = yes ] || {
    printf 'Set UEBA_DEMO_CONFIRM=yes to insert synthetic accounts/events into the local lab.\n' >&2
    return 1
  }
  [ "$COMPOSE_PROJECT_NAME" = flare-local-elk ] || {
    printf 'UEBA demo seeding is restricted to the flare-local-elk Compose project.\n' >&2
    return 1
  }
  [[ "$dataset" =~ ^[a-z0-9][a-z0-9_-]{3,23}$ ]] || {
    printf 'Invalid UEBA_DEMO_DATASET_ID.\n' >&2
    return 1
  }
  [ -n "$(compose ps -q db)" ] || {
    printf 'The local lab database must be running before seeding.\n' >&2
    return 1
  }
  local generator=(python3 "${ROOT_DIR}/observability/scripts/seed-ueba-demo.py" "$mode" --dataset-id "$dataset")
  if [ "$mode" = normal ]; then
    command -v htpasswd >/dev/null || { printf 'htpasswd is required for demo password hashing.\n' >&2; return 1; }
    local demo_password=${UEBA_DEMO_PASSWORD:-DemoOnly#2026} prehash encoded
    prehash=$(printf '%s' "$demo_password" | openssl dgst -sha256 -binary | openssl base64 -A | tr -d '=')
    encoded=$(printf '%s\n' "$prehash" | htpasswd -niBC 12 demo)
    generator+=(--password-hash "{bcrypt-sha256}${encoded#demo:}")
  else
    local account_id="ueba-demo-${dataset}-1" account_count
    # The single-quoted program expands inside the DB container, not here.
    # shellcheck disable=SC2016
    account_count=$(printf 'SELECT COUNT(*) FROM tbl_nguoi_dung WHERE id = "%s";\n' "$account_id" |
      compose exec -T db sh -ceu 'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -N -s -u "$MYSQL_USER" "$MYSQL_DATABASE"')
    [ "$account_count" = 1 ] || {
      printf 'Seed normal history for dataset %s before abnormal traffic.\n' "$dataset" >&2
      return 1
    }
  fi
  # The single-quoted program expands inside the DB container, not here.
  # shellcheck disable=SC2016
  "${generator[@]}" |
    compose exec -T db sh -ceu 'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER" "$MYSQL_DATABASE"' || return $?
  printf 'UEBA %s demo data inserted into local project %s (dataset %s).\n' "$mode" "$COMPOSE_PROJECT_NAME" "$dataset"
  if [ "$mode" = normal ]; then
    printf 'Demo login: ueba_demo_%s_1; password from UEBA_DEMO_PASSWORD (default DemoOnly#2026).\n' "$dataset"
  fi
}

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
  demo-normal) seed_ueba_demo normal || exit $? ;;
  demo-abnormal) seed_ueba_demo abnormal || exit $? ;;
  verify-ueba) "${ROOT_DIR}/observability/scripts/verify-ueba-demo.sh" "${2:-}" || exit $? ;;
  purge) purge ;;
  all) all ;;
  *) printf 'Usage: %s {bootstrap|validate|up|verify|evidence|down|demo-normal|demo-abnormal|verify-ueba|purge|all}\n' "$0" >&2; exit 2 ;;
esac
