#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

for binary in docker jq stat; do
  command -v "$binary" >/dev/null 2>&1 || {
    printf 'Missing required command: %s\n' "$binary" >&2
    exit 1
  }
done

project=${RUNTIME_REGRESSION_PROJECT_NAME:-"pbl4-regression-$(date +%s)-$$"}
[[ "$project" =~ ^pbl4-regression-[a-z0-9][a-z0-9_-]*$ ]] || {
  printf 'RUNTIME_REGRESSION_PROJECT_NAME must start with pbl4-regression- and contain only lowercase project characters.\n' >&2
  exit 1
}

runtime_dir=$(mktemp -d)
bind_dir="${runtime_dir}/nginx-logs"
override="${runtime_dir}/bind-override.yml"
runner_image="${project}-logrotate"
host_uid=$(id -u)
host_gid=$(id -g)
mkdir -m 0755 "$bind_dir"

cat >"$override" <<EOF
services:
  nginx-logs-init:
    volumes:
      - ${bind_dir}:/var/log/nginx
EOF

base_args=(--env-file .env.e2e.example --project-name "$project" -f docker-compose.yml)
bind_args=("${base_args[@]}" -f "$override")

cleanup() {
  if docker image inspect "$runner_image" >/dev/null 2>&1; then
    docker run --rm --name "${project}-permission-cleanup" --network none \
      --read-only --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --user 0:1000 \
      --cap-add DAC_OVERRIDE \
      --entrypoint sh -v "${runtime_dir}:/cleanup" "$runner_image" \
      -ceu 'chown -R "$1:$2" /cleanup && chmod -R u+rwX /cleanup' -- "$host_uid" "$host_gid" \
      >/dev/null 2>&1 || true
  else
    docker compose "${bind_args[@]}" run --rm --no-deps --entrypoint sh nginx-logs-init \
      -ceu 'chown -R "$1:$2" /var/log/nginx && chmod -R u+rwX /var/log/nginx' -- "$host_uid" "$host_gid" \
      >/dev/null 2>&1 || true
  fi
  docker compose "${bind_args[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker image rm "$runner_image" >/dev/null 2>&1 || true
  rm -rf "$runtime_dir"
}
trap cleanup EXIT

run_init_twice() {
  local variant=$1
  shift
  local args=("$@")
  docker compose "${args[@]}" up --no-deps --force-recreate nginx-logs-init
  docker compose "${args[@]}" up --no-deps --force-recreate nginx-logs-init
  docker compose "${args[@]}" run --rm --no-deps --entrypoint sh nginx-logs-init -ceu '
    actual=$(stat -c "%u:%g %a" /var/log/nginx)
    [ "$actual" = "101:1000 2750" ] || { echo "unexpected ownership for '"$variant"': $actual" >&2; exit 1; }
  '
}

run_init_twice named-volume "${base_args[@]}"
run_init_twice aws-bind "${bind_args[@]}"

actual_host=$(stat -c '%u:%g %a' "$bind_dir")
[ "$actual_host" = '101:1000 2750' ] || {
  printf 'Unexpected bind ownership after repeated initialization: %s\n' "$actual_host" >&2
  exit 1
}

docker build --pull=false --tag "$runner_image" --file observability/tests/logrotate/Dockerfile .
state_dir="${runtime_dir}/state"
mkdir -m 0777 "$state_dir"

docker run --rm --name "${project}-logrotate-setup" --network none \
  --entrypoint sh -v "${bind_dir}:/opt/flare/nginx-logs" "$runner_image" -ceu '
    printf "%s\n" before-rotation-marker > /opt/flare/nginx-logs/access.json.log
    : > /opt/flare/nginx-logs/error.log
    chown 101:1000 /opt/flare/nginx-logs/*.log
    chmod 0640 /opt/flare/nginx-logs/*.log
  '

docker run --rm --name "${project}-logrotate-success" --network none \
  -e FAKE_DOCKER_LOG=/state/docker.calls \
  -v "${bind_dir}:/opt/flare/nginx-logs" -v "${state_dir}:/state" \
  "$runner_image" --verbose --force --state /state/status /etc/nginx-access

docker run --rm --name "${project}-logrotate-assert" --network none \
  --entrypoint sh -v "${bind_dir}:/opt/flare/nginx-logs:ro" -v "${state_dir}:/state:ro" \
  "$runner_image" -ceu '
    current=$(stat -c "%u:%g %a" /opt/flare/nginx-logs/access.json.log)
    [ "$current" = "101:1000 640" ]
    grep -R -F before-rotation-marker /opt/flare/nginx-logs/access.json.log-* >/dev/null
    grep -F -- "compose --project-name flare --project-directory /opt/flare kill -s USR1 nginx" /state/docker.calls >/dev/null
  '

docker run --rm --name "${project}-logrotate-refill" --network none \
  --entrypoint sh -v "${bind_dir}:/opt/flare/nginx-logs" "$runner_image" \
  -ceu 'rm -f /opt/flare/nginx-logs/access.json.log-*; printf "%s\n" signal-failure-marker > /opt/flare/nginx-logs/access.json.log'

if docker run --rm --name "${project}-logrotate-signal-failure" --network none \
  -e FAKE_DOCKER_LOG=/state/docker.calls -e FAKE_DOCKER_KILL_FAIL=yes \
  -v "${bind_dir}:/opt/flare/nginx-logs" -v "${state_dir}:/state" \
  "$runner_image" --verbose --force --state /state/status /etc/nginx-access; then
  printf 'Logrotate unexpectedly hid an Nginx signal failure.\n' >&2
  exit 1
fi
tail -n 1 "${state_dir}/docker.calls" | grep -F -- 'kill -s USR1 nginx' >/dev/null || {
  printf 'The signal-failure scenario did not reach the Nginx signal command.\n' >&2
  exit 1
}

fake_bin="${runtime_dir}/fake-bin"
fixture_calls="${runtime_dir}/fixture.calls"
mkdir -m 0755 "$fake_bin"
cat >"${fake_bin}/docker" <<'EOF'
#!/bin/sh
set -eu
cat >/dev/null
printf '%s\n' "$*" >>"${DOCKER_CAPTURE:?}"
EOF
chmod 0755 "${fake_bin}/docker"
LOCAL_FIXTURE_CONFIRM=yes COMPOSE_PROJECT_NAME="$project" DOCKER_CAPTURE="$fixture_calls" \
  PATH="${fake_bin}:$PATH" observability/scripts/replay-5xx-fixture.sh >/dev/null
[ "$(wc -l <"$fixture_calls")" -eq 6 ]
if grep -F -- '--project-name flare-local-elk' "$fixture_calls" >/dev/null; then
  printf 'The fixture ignored the caller-provided Compose project.\n' >&2
  exit 1
fi
[ "$(grep -F -c -- "--project-name ${project}" "$fixture_calls")" -eq 6 ]

printf 'Docker init idempotency, project isolation, AWS bind ownership and logrotate runtime regressions passed for %s.\n' "$project"
