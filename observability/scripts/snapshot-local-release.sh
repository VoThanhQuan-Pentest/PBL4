#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"
mode=${1:-full}
[[ "$mode" = full || "$mode" = --source-only ]] || { printf 'Usage: %s [--source-only]\n' "$0" >&2; exit 2; }
export OBSERVABILITY_ROOT_DIR="$ROOT_DIR"
export FILEBEAT_CERTS_DIR="$ROOT_DIR/.secrets/observability/web"
export COMPOSE_PROJECT_NAME=flare-local-elk
compose=(docker compose --env-file .env.e2e.example -p flare-local-elk --profile observability
  -f docker-compose.yml -f docker-compose.e2e.yml
  -f observability/docker-compose.monitor.yml -f observability/docker-compose.local.yml)
umask 077
install -d -m 0700 observability/runtime/private-backups
dest=$(mktemp -d "$ROOT_DIR/observability/runtime/private-backups/release-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
if [ "$mode" = full ]; then
  # shellcheck disable=SC2016
  pending=$(printf "SELECT COUNT(*) FROM siem_ueba_model_jobs WHERE status IN ('QUEUED','RUNNING');\n" |
    "${compose[@]}" exec -T db sh -ceu 'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -Ns -u "$MYSQL_USER" "$MYSQL_DATABASE"')
  [ "$pending" = 0 ] || { printf 'Finish training before taking a model backup.\n' >&2; exit 1; }
  "$ROOT_DIR/observability/scripts/backup-local-db.sh" >"$dest/database-backup.txt"
  db_backup=$(sed -n 's/^Private local DB backup ready: //p' "$dest/database-backup.txt")
  case "$db_backup" in
    "$ROOT_DIR/observability/runtime/private-backups/"*) ;;
    *) printf 'Database backup path escaped private runtime storage.\n' >&2; exit 1 ;;
  esac
  [ -f "$db_backup" ] && [ ! -L "$db_backup" ] && [ "$(stat -c '%a' "$db_backup")" = 600 ] || {
    printf 'Database backup is missing or not private.\n' >&2; exit 1;
  }
  gzip -t "$db_backup"
  "$ROOT_DIR/observability/scripts/backup-kibana-before-import.sh" >"$dest/kibana-backup.txt"
  kibana_backup=$(sed -n 's/^Existing Kibana dashboards and [0-9][0-9]* rules backed up privately to //p' "$dest/kibana-backup.txt")
  case "$kibana_backup" in
    "$ROOT_DIR/observability/runtime/private-backups/"*) ;;
    *) printf 'Kibana backup path escaped private runtime storage.\n' >&2; exit 1 ;;
  esac
  [ -d "$kibana_backup" ] && [ ! -L "$kibana_backup" ] && [ "$(stat -c '%a' "$kibana_backup")" = 700 ] || {
    printf 'Kibana backup directory is missing or not private.\n' >&2; exit 1;
  }
  saved_objects="$kibana_backup/saved-objects.ndjson"
  detection_rules="$kibana_backup/detection-rules.ndjson"
  [ -f "$saved_objects" ] && [ ! -L "$saved_objects" ] && [ "$(stat -c '%a' "$saved_objects")" = 600 ] || {
    printf 'Kibana saved-object export is missing or not private.\n' >&2; exit 1;
  }
  [ -f "$detection_rules" ] && [ ! -L "$detection_rules" ] && [ "$(stat -c '%a' "$detection_rules")" = 600 ] || {
    printf 'Kibana detection-rule export is missing or not private.\n' >&2; exit 1;
  }
  jq -s -e '([.[] | select(.type == "dashboard" and (.id == "flare-overview" or .id == "flare-geoip" or .id == "flare-security"))] | length) == 3' \
    "$saved_objects" >/dev/null || { printf 'Kibana dashboard backup is incomplete.\n' >&2; exit 1; }
  exported_rules=$(jq -s 'map(select(.rule_id != null)) | length' "$detection_rules")
  reported_rules=$(jq -s 'map(select(has("exported_rules_count")) | .exported_rules_count) | .[0] // -1' "$detection_rules")
  [ "$exported_rules" -gt 0 ] && [ "$exported_rules" = "$reported_rules" ] || {
    printf 'Kibana detection-rule backup is incomplete.\n' >&2; exit 1;
  }
  "${compose[@]}" exec -T ueba-worker tar -C /var/lib/ueba -czf - . >"$dest/ueba-models.tar.gz"
  gzip -t "$dest/ueba-models.tar.gz"
  printf 'Full source and local data checkpoint.\n' >"$dest/coverage.txt"
else
  printf 'SOURCE ONLY. This invocation did not back up DB, Kibana or UEBA model. Earlier backups remain separate.\n' >"$dest/coverage.txt"
fi
# Include the dirty source tree, but never ignored runtime/secrets or Terraform state.
git ls-files -z --cached --others --exclude-standard |
  while IFS= read -r -d '' path; do
    filename=${path##*/}
    case "$filename" in
      .env.example|.env.*.example) ;;
      .env|.env.*) continue ;;
    esac
    case "$path" in
      .secrets/*|.env|*.tfstate*|*.tfvars|*.tfvars.json|*.tfplan|*.key|*.pem|observability/runtime/*|audit-results/*) continue ;;
    esac
    [ ! -f "$path" ] || printf '%s\0' "$path"
  done >"$dest/source-files.list"
tar --null --verbatim-files-from -czf "$dest/source.tar.gz" -T "$dest/source-files.list"
gzip -t "$dest/source.tar.gz"
docker ps --filter label=com.docker.compose.project=flare-local-elk -q |
  xargs -r docker inspect --format '{{.Name}} {{.Image}}' >"$dest/runtime-images.txt"
git status --porcelain=v1 >"$dest/worktree-status.txt"
git rev-parse HEAD >"$dest/base-commit.txt"
sha256sum "$dest/source.tar.gz" >"$dest/SHA256SUMS"
if [ -f "$dest/ueba-models.tar.gz" ]; then
  sha256sum "$dest/ueba-models.tar.gz" >>"$dest/SHA256SUMS"
  sha256sum "$db_backup" "$saved_objects" "$detection_rules" >>"$dest/SHA256SUMS"
fi
chmod 0600 "$dest/"*
printf 'Private %s checkpoint: %s\n' "$mode" "$dest"
