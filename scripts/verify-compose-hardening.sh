#!/bin/sh
set -eu

# Validate the resolved Compose variants rather than only grepping source. This
# prevents a later override from quietly restoring MySQL entrypoint scripts or
# exposing the application container directly.
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

service_block() {
  service_name=$1
  awk -v service_name="$service_name" '
    $0 == "  " service_name ":" { inside = 1; next }
    inside && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
    inside { print }
  '
}

assert_safe_resolved_compose() {
  variant_name=$1
  rendered_config=$2

  case "$rendered_config" in
    *docker-entrypoint-initdb.d*|*db-init*)
      fail "$variant_name Compose config mounts a legacy MySQL init script; Flyway must be the only schema source."
      ;;
  esac

  if printf '%s\n' "$rendered_config" | service_block app | grep -q '^[[:space:]]*ports:'; then
    fail "$variant_name Compose config exposes the application container directly; only Nginx may publish HTTP."
  fi

  db_block=$(printf '%s\n' "$rendered_config" | service_block db)
  if printf '%s\n' "$db_block" | grep -q '^[[:space:]]*ports:' \
      && ! printf '%s\n' "$db_block" | grep -q 'host_ip: 127\.0\.0\.1'; then
    fail "$variant_name Compose config publishes MySQL outside loopback."
  fi
}

assert_digest_pins() {
  if awk '
    $1 == "image:" && $2 !~ /@sha256:/ {
      print FILENAME ":" FNR ": image is not digest pinned: " $0
      invalid = 1
    }
    END { exit invalid }
  ' docker-compose.yml docker-compose.dev.yml docker-compose.e2e.yml observability/docker-compose.monitor.yml; then
    :
  else
    fail "All Compose runtime images must use immutable SHA-256 digests."
  fi

  if awk '
    $1 == "FROM" && $2 !~ /@sha256:/ {
      print FILENAME ":" FNR ": base image is not digest pinned: " $0
      invalid = 1
    }
    END { exit invalid }
  ' backend/Dockerfile nginx/Dockerfile; then
    :
  else
    fail "All Dockerfile base images must use immutable SHA-256 digests."
  fi
}

base_config=$(docker compose --env-file .env.example config)
dev_config=$(docker compose --env-file .env.example -f docker-compose.yml -f docker-compose.dev.yml config)
e2e_config=$(docker compose --env-file .env.e2e.example -f docker-compose.yml -f docker-compose.e2e.yml config)

assert_safe_resolved_compose base "$base_config"
assert_safe_resolved_compose dev "$dev_config"
assert_safe_resolved_compose e2e "$e2e_config"
assert_digest_pins

printf '%s\n' 'Compose hardening checks passed.'
