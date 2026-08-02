#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

project=${REDIS_MIGRATION_TEST_PROJECT_NAME:-"pbl4-redis-migration-$(date +%s)-$$"}
[[ "$project" =~ ^pbl4-redis-migration-[a-z0-9][a-z0-9_-]*$ ]] || {
  printf 'REDIS_MIGRATION_TEST_PROJECT_NAME must be an isolated pbl4-redis-migration-* project.\n' >&2
  exit 1
}

# The production Compose file deliberately uses a configurable private subnet.
# Pick an isolated test subnet so this regression can coexist with user stacks.
export FLARE_INTERNAL_SUBNET=${REDIS_MIGRATION_TEST_SUBNET:-"10.254.$(( $$ % 200 + 1 )).0/24"}

runtime_dir=$(mktemp -d)
legacy_compose="${runtime_dir}/legacy.yml"
state_dir="${runtime_dir}/state"
cat >"$legacy_compose" <<'EOF'
services:
  redis:
    image: redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99
    command: ["redis-server", "--save", "20", "1", "--loglevel", "warning", "--requirepass", "${REDIS_PASSWORD:?}"]
    environment:
      REDIS_PASSWORD: ${REDIS_PASSWORD:?}
    volumes:
      - legacy-redis-data:/data
    healthcheck:
      test: ["CMD-SHELL", "redis-cli -a \"$${REDIS_PASSWORD}\" ping | grep PONG"]
      interval: 2s
      timeout: 2s
      retries: 20
volumes:
  legacy-redis-data:
EOF

legacy_args=(--env-file .env.e2e.example --project-name "$project" -f "$legacy_compose")
current_args=(--env-file .env.e2e.example --project-name "$project" -f docker-compose.yml)
migration_env=(
  COMPOSE_PROJECT_NAME="$project"
  REDIS_MIGRATION_ENV_FILE="${ROOT_DIR}/.env.e2e.example"
  REDIS_MIGRATION_COMPOSE_FILES="${ROOT_DIR}/docker-compose.yml"
  REDIS_MIGRATION_STATE_DIR="$state_dir"
)

cleanup() {
  local backup=''
  [ ! -r "${state_dir}/state.json" ] || backup=$(jq -r '.backup_volume // empty' "${state_dir}/state.json")
  docker compose "${current_args[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker compose "${legacy_args[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  case "$backup" in "${project}"_redis-data-rollback-*) docker volume rm "$backup" >/dev/null 2>&1 || true ;; esac
  rm -rf "$runtime_dir"
}
trap cleanup EXIT

docker compose "${legacy_args[@]}" up --wait --wait-timeout 60 -d redis
docker compose "${legacy_args[@]}" exec -T redis sh -ceu '
  export REDISCLI_AUTH="$REDIS_PASSWORD"
  redis-cli SET fixture:persistent preserved >/dev/null
  redis-cli SET fixture:ttl expires-later EX 600 >/dev/null
  redis-cli SAVE >/dev/null
'

docker compose "${legacy_args[@]}" stop redis >/dev/null

if env "${migration_env[@]}" observability/scripts/migrate-redis-volume.sh check; then
  printf 'Migration check did not detect the legacy volume.\n' >&2
  exit 1
fi

target_volume=$(docker compose "${current_args[@]}" config --format json | jq -er '.volumes["redis-data"].name')
docker volume create --label "com.docker.compose.project=${project}" --label 'com.docker.compose.volume=redis-data' "$target_volume" >/dev/null
docker run --rm --name "${project}-nonempty-target" --network none --entrypoint sh \
  -v "${target_volume}:/data" redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99 \
  -ceu ': > /data/refuse-overwrite'
if env "${migration_env[@]}" REDIS_VOLUME_MIGRATION_CONFIRM=yes \
  observability/scripts/migrate-redis-volume.sh prepare; then
  printf 'Migration overwrote a non-empty target volume.\n' >&2
  exit 1
fi
docker volume rm "$target_volume" >/dev/null

env "${migration_env[@]}" REDIS_VOLUME_MIGRATION_CONFIRM=yes \
  observability/scripts/migrate-redis-volume.sh prepare
env "${migration_env[@]}" observability/scripts/migrate-redis-volume.sh verify

redis_value() {
  docker compose "${current_args[@]}" exec -T redis sh -ceu '
    export REDISCLI_AUTH="$REDIS_PASSWORD"
    redis-cli --raw "$@"
  ' -- "$@"
}

[ "$(redis_value GET fixture:persistent)" = preserved ]
[ "$(redis_value GET fixture:ttl)" = expires-later ]
[ "$(redis_value TTL fixture:ttl)" -gt 0 ]

docker compose "${current_args[@]}" up --wait --wait-timeout 60 -d --force-recreate --no-deps redis >/dev/null
[ "$(redis_value GET fixture:persistent)" = preserved ]

env "${migration_env[@]}" REDIS_VOLUME_MIGRATION_CONFIRM=yes \
  observability/scripts/migrate-redis-volume.sh prepare
redis_value SET fixture:persistent changed-after-migration >/dev/null
env "${migration_env[@]}" REDIS_VOLUME_MIGRATION_CONFIRM=yes \
  observability/scripts/migrate-redis-volume.sh rollback
[ "$(redis_value GET fixture:persistent)" = preserved ]
env "${migration_env[@]}" observability/scripts/migrate-redis-volume.sh verify

printf 'Redis named-volume migration, restart persistence, idempotency and rollback passed for %s.\n' "$project"
