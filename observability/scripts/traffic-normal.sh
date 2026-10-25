#!/usr/bin/env bash
set -Eeuo pipefail

# Generate benign lab traffic against a local or explicitly allowlisted target.
# Optional login values are read only from the environment and sent in the POST
# body; they are never written to a URL or log file.
: "${FLARE_LAB_TARGET:?Set FLARE_LAB_TARGET to the group-owned lab HTTP origin}"
TARGET=${FLARE_LAB_TARGET%/}
[[ "$TARGET" =~ ^https?://([A-Za-z0-9.-]+)(:[0-9]{1,5})?$ ]] || {
  printf 'FLARE_LAB_TARGET must be one HTTP(S) origin without a path, query or userinfo.\n' >&2
  exit 1
}
target_host=${BASH_REMATCH[1]}
case "$target_host" in
  localhost|localhost:*|127.0.0.1|127.0.0.1:*) ;;
  *)
    : "${FLARE_LAB_ALLOWED_HOST:?Set FLARE_LAB_ALLOWED_HOST for a non-local target}"
    [ "$target_host" = "$FLARE_LAB_ALLOWED_HOST" ] || { printf 'Target host is not the explicit allowlist host.\n' >&2; exit 1; }
    [ "${I_OWN_THIS_TARGET:-}" = "yes" ] || { printf 'Set I_OWN_THIS_TARGET=yes after confirming ownership.\n' >&2; exit 1; }
    ;;
esac

curl --fail --silent --show-error --max-time 10 -o /dev/null "${TARGET}/"
curl --fail --silent --show-error --max-time 10 -o /dev/null "${TARGET}/api/products"
curl --fail --silent --show-error --max-time 10 -o /dev/null "${TARGET}/api/health"

if [ -n "${DEMO_LOGIN_USERNAME:-}" ] || [ -n "${DEMO_LOGIN_PASSWORD:-}" ]; then
  : "${DEMO_LOGIN_USERNAME:?Set both DEMO_LOGIN_USERNAME and DEMO_LOGIN_PASSWORD, or neither}"
  : "${DEMO_LOGIN_PASSWORD:?Set both DEMO_LOGIN_USERNAME and DEMO_LOGIN_PASSWORD, or neither}"
  command -v jq >/dev/null 2>&1 || { printf 'jq is required for the optional login flow.\n' >&2; exit 1; }

  cookie_file=$(mktemp)
  trap 'rm -f "$cookie_file"' EXIT
  chmod 0600 "$cookie_file"
  csrf_token=$(curl --fail --silent --show-error --max-time 10 \
    -c "$cookie_file" "${TARGET}/api/auth/csrf" | jq -er '.token')
  login_payload=$(jq -nc \
    --arg username "$DEMO_LOGIN_USERNAME" \
    --arg password "$DEMO_LOGIN_PASSWORD" \
    '{username:$username,password:$password}')
  printf '%s' "$login_payload" | curl --fail --silent --show-error --max-time 10 \
    -o /dev/null -b "$cookie_file" \
    -H "X-XSRF-TOKEN: ${csrf_token}" \
    -H 'Content-Type: application/json' \
    --data-binary @- "${TARGET}/api/auth/login"
fi

printf 'Normal traffic sent to %s\n' "$TARGET"
