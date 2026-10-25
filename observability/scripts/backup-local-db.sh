#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
project=${COMPOSE_PROJECT_NAME:-flare-local-elk}
[ "$project" = flare-local-elk ] || {
  printf 'Database backup is restricted to the local flare-local-elk project.\n' >&2
  exit 2
}
export OBSERVABILITY_ROOT_DIR="$ROOT_DIR"
export FILEBEAT_CERTS_DIR="${ROOT_DIR}/.secrets/observability/web"
compose_args=(--env-file "${ROOT_DIR}/.env.e2e.example" --project-name "$project" --profile observability
  -f "${ROOT_DIR}/docker-compose.yml" -f "${ROOT_DIR}/docker-compose.e2e.yml"
  -f "${ROOT_DIR}/observability/docker-compose.monitor.yml"
  -f "${ROOT_DIR}/observability/docker-compose.local.yml")
compose() { docker compose "${compose_args[@]}" "$@"; }
[ -n "$(compose ps -q db)" ] || { printf 'Local DB container is not running.\n' >&2; exit 1; }

umask 077
backup_dir="${ROOT_DIR}/observability/runtime/private-backups"
install -d -m 0700 "$backup_dir"
temporary=$(mktemp "${backup_dir}/mysql-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX.sql.gz.partial")
cleanup() { [ -z "${temporary:-}" ] || rm -f -- "$temporary"; }
trap cleanup EXIT
# The single-quoted program expands inside the DB container, not here.
# shellcheck disable=SC2016
compose exec -T db sh -ceu '
  MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqldump --single-transaction --quick \
    --no-tablespaces --routines --triggers --events -u root "$MYSQL_DATABASE"
' | gzip -c >"$temporary"
gzip -t "$temporary"
final=${temporary%.partial}
mv -- "$temporary" "$final"
chmod 0600 "$final"
temporary=
printf 'Private local DB backup ready: %s\n' "$final"
printf 'It contains user data and password hashes; do not upload or attach it as evidence.\n'
