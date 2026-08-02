#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
REDIS_IMAGE='redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99'
action=${1:-}

case "$action" in check|prepare|verify|rollback) ;; *)
  printf 'Usage: COMPOSE_PROJECT_NAME=<project> %s {check|prepare|verify|rollback}\n' "$0" >&2
  exit 2
esac

: "${COMPOSE_PROJECT_NAME:?Set the exact Compose project name before inspecting or migrating Redis}"
[[ "$COMPOSE_PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || {
  printf 'COMPOSE_PROJECT_NAME contains unsupported characters.\n' >&2
  exit 2
}

for binary in docker jq openssl flock sha256sum; do
  command -v "$binary" >/dev/null 2>&1 || { printf 'Missing required command: %s\n' "$binary" >&2; exit 1; }
done

env_file=${REDIS_MIGRATION_ENV_FILE:-"${ROOT_DIR}/.env"}
[ -r "$env_file" ] || { printf 'Redis migration env file is not readable: %s\n' "$env_file" >&2; exit 1; }
compose_files=${REDIS_MIGRATION_COMPOSE_FILES:-"${ROOT_DIR}/docker-compose.yml:${ROOT_DIR}/observability/docker-compose.web-aws.yml"}
compose_args=(--env-file "$env_file" --project-name "$COMPOSE_PROJECT_NAME")
IFS=: read -r -a files <<<"$compose_files"
for file in "${files[@]}"; do
  [ -r "$file" ] || { printf 'Compose file is not readable: %s\n' "$file" >&2; exit 1; }
  compose_args+=(-f "$file")
done
compose() { docker compose "${compose_args[@]}" "$@"; }

state_dir=${REDIS_MIGRATION_STATE_DIR:-"${ROOT_DIR}/observability/runtime/redis-migration"}
state_file="${state_dir}/state.json"
umask 077
install -d -m 0700 "$state_dir"
exec 9>"${state_dir}/migration.lock"
flock -n 9 || { printf 'Another Redis migration command is already running.\n' >&2; exit 1; }

rendered=$(compose config --format json)
target_volume=$(jq -er '.volumes["redis-data"].name' <<<"$rendered")

redis_container() { compose ps --all -q redis; }
mount_json() {
  local container=$1
  docker inspect "$container" --format '{{json .Mounts}}' | jq -cer '[.[] | select(.Destination=="/data")] | if length==1 then .[0] else error("Redis must have exactly one /data mount") end'
}
redis_command() {
  # Expansion belongs to the Redis container shell.
  # shellcheck disable=SC2016
  compose exec -T redis sh -ceu '
    export REDISCLI_AUTH="$REDIS_PASSWORD"
    exec redis-cli "$@"
  ' -- "$@"
}
volume_exists() { docker volume inspect "$1" >/dev/null 2>&1; }
create_target_volume() {
  docker volume create \
    --label "com.docker.compose.project=${COMPOSE_PROJECT_NAME}" \
    --label 'com.docker.compose.volume=redis-data' \
    "$1" >/dev/null
}
volume_is_empty() {
  docker run --rm --name "${COMPOSE_PROJECT_NAME}-redis-volume-check-$$" --network none --read-only --cap-drop ALL \
    --entrypoint sh -v "$1:/data:ro" "$REDIS_IMAGE" -ceu '[ -z "$(find /data -mindepth 1 -maxdepth 1 -print -quit)" ]'
}
copy_snapshot() {
  local source=$1 target=$2 backup=$3
  docker run --rm --name "${COMPOSE_PROJECT_NAME}-redis-volume-copy-$$" --network none --read-only \
    --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE --user 0:0 --entrypoint sh \
    -v "${source}:/source:ro" -v "${target}:/target" -v "${backup}:/backup" "$REDIS_IMAGE" -ceu '
      test -s /source/dump.rdb
      test -z "$(find /target -mindepth 1 -maxdepth 1 -print -quit)"
      test -z "$(find /backup -mindepth 1 -maxdepth 1 -print -quit)"
      cp -p /source/dump.rdb /target/dump.rdb
      cp -p /source/dump.rdb /backup/dump.rdb
    '
}
snapshot_checksums() {
  local source=$1 target=$2 backup=$3
  docker run --rm --name "${COMPOSE_PROJECT_NAME}-redis-volume-hash-$$" --network none --read-only --cap-drop ALL \
    --cap-add DAC_OVERRIDE \
    --entrypoint sh -v "${source}:/source:ro" -v "${target}:/target:ro" -v "${backup}:/backup:ro" \
    "$REDIS_IMAGE" -ceu '
      sha256sum /source/dump.rdb /target/dump.rdb /backup/dump.rdb | awk "{print \$1}"
    '
}
restore_backup() {
  local backup=$1 target=$2
  create_target_volume "$target"
  docker run --rm --name "${COMPOSE_PROJECT_NAME}-redis-volume-restore-$$" --network none --read-only \
    --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE --user 0:0 --entrypoint sh \
    -v "${backup}:/backup:ro" -v "${target}:/target" "$REDIS_IMAGE" -ceu '
      test -s /backup/dump.rdb
      find /target -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
      cp -p /backup/dump.rdb /target/dump.rdb
    '
}
wait_service_ready() {
  local service=$1 container status
  container=$(compose ps -q "$service")
  [ -n "$container" ] || { printf 'Expected service is missing after restart: %s\n' "$service" >&2; return 1; }
  for _ in $(seq 1 60); do
    status=$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')
    case "$status" in healthy|running) return 0 ;; unhealthy|exited|dead) return 1 ;; esac
    sleep 2
  done
  printf 'Timed out waiting for service readiness: %s\n' "$service" >&2
  return 1
}
wait_container_ready() {
  local container=$1 status
  for _ in $(seq 1 60); do
    status=$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')
    case "$status" in healthy|running) return 0 ;; unhealthy|exited|dead) return 1 ;; esac
    sleep 2
  done
  printf 'Timed out waiting for Redis container readiness: %s\n' "$container" >&2
  return 1
}
start_previous_services() {
  local app_was_running=$1 nginx_was_running=$2
  if [ "$app_was_running" = true ]; then compose start app >/dev/null; wait_service_ready app; fi
  if [ "$nginx_was_running" = true ]; then compose start nginx >/dev/null; wait_service_ready nginx; fi
}
write_state() {
  local status=$1 source=$2 target=$3 backup=$4 marker=$5 checksum=$6
  local tmp="${state_file}.tmp"
  jq -nc --arg status "$status" --arg source "$source" --arg target "$target" --arg backup "$backup" \
    --arg marker "$marker" --arg checksum "$checksum" --arg updated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{schema_version:1,status:$status,source_volume:$source,target_volume:$target,backup_volume:$backup,marker_key:$marker,snapshot_sha256:$checksum,updated_at:$updated}' >"$tmp"
  chmod 0600 "$tmp"
  mv "$tmp" "$state_file"
}

check_migration() {
  local container mount source type
  container=$(redis_container)
  if [ -z "$container" ]; then
    printf 'No Redis container exists; no legacy live volume requires migration. Target volume: %s\n' "$target_volume"
    return 0
  fi
  mount=$(mount_json "$container")
  source=$(jq -r '.Name // .Source' <<<"$mount")
  type=$(jq -r '.Type' <<<"$mount")
  [ "$type" = volume ] || { printf 'Refusing migration: Redis /data is a %s mount, not a Docker volume.\n' "$type" >&2; return 1; }
  if [ "$source" = "$target_volume" ]; then
    printf 'Redis already uses the declared project volume %s.\n' "$target_volume"
    return 0
  fi
  printf 'Redis migration required: legacy volume %s -> %s.\n' "$source" "$target_volume" >&2
  return 1
}

prepare_migration() {
  [ "${REDIS_VOLUME_MIGRATION_CONFIRM:-}" = yes ] || {
    printf 'Set REDIS_VOLUME_MIGRATION_CONFIRM=yes to perform the maintenance cutover.\n' >&2
    return 1
  }

  local old_container mount source type backup marker marker_value app_was_running=false nginx_was_running=false
  local phase=before-stop checksum_lines source_checksum target_checksum backup_checksum
  old_container=$(redis_container)
  [ -n "$old_container" ] || { printf 'A Redis container must exist before a legacy migration.\n' >&2; return 1; }
  mount=$(mount_json "$old_container")
  source=$(jq -r '.Name // .Source' <<<"$mount")
  type=$(jq -r '.Type' <<<"$mount")
  [ "$type" = volume ] || { printf 'Refusing migration from non-volume Redis data.\n' >&2; return 1; }
  if [ "$source" = "$target_volume" ]; then
    printf 'Redis already uses %s; no migration was performed.\n' "$target_volume"
    return 0
  fi

  if volume_exists "$target_volume" && ! volume_is_empty "$target_volume"; then
    printf 'Refusing to overwrite non-empty target volume %s.\n' "$target_volume" >&2
    return 1
  fi

  if [ "$(docker inspect "$old_container" --format '{{.State.Running}}')" != true ]; then
    docker start "$old_container" >/dev/null
    wait_container_ready "$old_container"
  fi

  backup="${COMPOSE_PROJECT_NAME}_redis-data-rollback-$(date -u +%Y%m%d%H%M%S)"
  marker="flare:migration:$(openssl rand -hex 12)"
  marker_value=$(openssl rand -hex 16)
  [ -z "$(compose ps --status running -q app)" ] || app_was_running=true
  [ -z "$(compose ps --status running -q nginx)" ] || nginx_was_running=true

  rollback_on_error() {
    local status=$?
    trap - ERR
    set +e
    printf 'Redis migration failed during %s; restoring the last consistent snapshot.\n' "$phase" >&2
    compose stop nginx app redis >/dev/null 2>&1
    if docker inspect "$old_container" >/dev/null 2>&1; then
      docker start "$old_container" >/dev/null
    elif volume_exists "$backup"; then
      restore_backup "$backup" "$target_volume"
      compose up --wait --wait-timeout 120 -d --force-recreate --no-deps redis >/dev/null
    fi
    start_previous_services "$app_was_running" "$nginx_was_running"
    write_state failed "$source" "$target_volume" "$backup" "$marker" "${source_checksum:-}"
    exit "$status"
  }
  trap rollback_on_error ERR

  phase=quiesce
  compose stop nginx app >/dev/null
  redis_command SET "$marker" "$marker_value" EX 900 >/dev/null
  redis_command SAVE >/dev/null
  phase=stop-legacy-redis
  compose stop redis >/dev/null

  phase=copy-snapshot
  create_target_volume "$target_volume"
  docker volume create --label "com.flare.redis-migration-project=${COMPOSE_PROJECT_NAME}" "$backup" >/dev/null
  copy_snapshot "$source" "$target_volume" "$backup"
  mapfile -t checksum_lines < <(snapshot_checksums "$source" "$target_volume" "$backup")
  [ "${#checksum_lines[@]}" -eq 3 ]
  source_checksum=${checksum_lines[0]}
  target_checksum=${checksum_lines[1]}
  backup_checksum=${checksum_lines[2]}
  [ "$source_checksum" = "$target_checksum" ] && [ "$source_checksum" = "$backup_checksum" ]
  write_state copied "$source" "$target_volume" "$backup" "$marker" "$source_checksum"

  phase=cutover
  compose up --wait --wait-timeout 120 -d --force-recreate --no-deps redis >/dev/null
  [ "$(redis_command GET "$marker")" = "$marker_value" ]
  marker_ttl=$(redis_command TTL "$marker")
  [ "$marker_ttl" -gt 0 ] && [ "$marker_ttl" -le 900 ]
  redis_command DEL "$marker" >/dev/null
  start_previous_services "$app_was_running" "$nginx_was_running"
  write_state completed "$source" "$target_volume" "$backup" "$marker" "$source_checksum"
  trap - ERR

  printf 'Redis migration completed. Source and rollback volumes were retained; target=%s backup=%s.\n' "$target_volume" "$backup"
}

verify_migration() {
  [ -r "$state_file" ] || { printf 'Redis migration state is missing.\n' >&2; return 1; }
  jq -e '.schema_version==1 and (.status=="completed" or .status=="rolled_back")' "$state_file" >/dev/null
  local container current expected backup
  container=$(redis_container)
  [ -n "$container" ] || { printf 'Redis container is missing.\n' >&2; return 1; }
  [ "$(docker inspect "$container" --format '{{.State.Running}}')" = true ] || {
    printf 'Redis container is not running.\n' >&2
    return 1
  }
  current=$(mount_json "$container" | jq -r '.Name // .Source')
  expected=$(jq -r '.target_volume' "$state_file")
  backup=$(jq -r '.backup_volume' "$state_file")
  [ "$current" = "$expected" ]
  volume_exists "$backup"
  [ "$(redis_command PING)" = PONG ]
  printf 'Redis named-volume verification passed; rollback volume is retained.\n'
}

rollback_migration() {
  [ "${REDIS_VOLUME_MIGRATION_CONFIRM:-}" = yes ] || {
    printf 'Set REDIS_VOLUME_MIGRATION_CONFIRM=yes to restore the recorded rollback snapshot.\n' >&2
    return 1
  }
  [ -r "$state_file" ] || { printf 'Redis migration state is missing.\n' >&2; return 1; }
  local source target backup marker app_was_running=false nginx_was_running=false
  source=$(jq -er '.source_volume' "$state_file")
  target=$(jq -er '.target_volume' "$state_file")
  backup=$(jq -er '.backup_volume' "$state_file")
  marker=$(jq -er '.marker_key' "$state_file")
  [ "$target" = "$target_volume" ] || { printf 'Recorded target does not match rendered Compose target.\n' >&2; return 1; }
  volume_exists "$backup" || { printf 'Recorded rollback volume is missing.\n' >&2; return 1; }
  [ -z "$(compose ps --status running -q app)" ] || app_was_running=true
  [ -z "$(compose ps --status running -q nginx)" ] || nginx_was_running=true
  compose stop nginx app redis >/dev/null
  restore_backup "$backup" "$target"
  compose up --wait --wait-timeout 120 -d --force-recreate --no-deps redis >/dev/null
  [ "$(redis_command EXISTS "$marker")" -eq 1 ]
  redis_command DEL "$marker" >/dev/null
  start_previous_services "$app_was_running" "$nginx_was_running"
  write_state rolled_back "$source" "$target" "$backup" "$marker" "$(jq -r '.snapshot_sha256' "$state_file")"
  printf 'Redis rollback snapshot restored into %s; no volume was deleted.\n' "$target"
}

case "$action" in
  check) check_migration ;;
  prepare) prepare_migration ;;
  verify) verify_migration ;;
  rollback) rollback_migration ;;
esac
