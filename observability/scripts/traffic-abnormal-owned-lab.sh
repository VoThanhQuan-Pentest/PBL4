#!/usr/bin/env bash
set -Eeuo pipefail

# This script is deliberately constrained to an explicit, group-owned target.
# It sends only low-volume, encoded lab requests; it never runs a scanner or
# tries to execute a payload. Required confirmation prevents accidental use on
# a third party.
: "${FLARE_LAB_TARGET:?Set FLARE_LAB_TARGET to the local or group-owned lab HTTP origin}"

TARGET=${FLARE_LAB_TARGET%/}
target_host=$(printf '%s' "$TARGET" | sed -E 's#^https?://##; s#/.*$##')
case "$target_host" in
  localhost|localhost:*|127.0.0.1|127.0.0.1:*) ;;
  *)
    : "${FLARE_LAB_ALLOWED_HOST:?Set FLARE_LAB_ALLOWED_HOST for a non-local target}"
    [ "$target_host" = "$FLARE_LAB_ALLOWED_HOST" ] || { printf 'Target host is not the explicit allowlist host.\n' >&2; exit 1; }
    [ "${I_OWN_THIS_TARGET:-}" = "yes" ] || { printf 'Set I_OWN_THIS_TARGET=yes after confirming ownership.\n' >&2; exit 1; }
    ;;
esac

request() {
  curl --silent --show-error --max-time 5 --output /dev/null --path-as-is "$@" || true
}

# 120 requests in about one minute: request-rate rule (medium).
for count in $(seq 1 120); do
  request "${TARGET}/?lab_request=${count}"
  sleep 0.45
done

# 25 explicit 404s: web-scan rule (medium).
for count in $(seq 1 25); do
  request "${TARGET}/api/lab-missing-${count}"
done

# Six failed fixture login attempts with a legitimate CSRF cookie/header. The
# password stays in the POST body and is never present in Nginx access JSON.
cookie_file=$(mktemp)
trap 'rm -f "$cookie_file"' EXIT
chmod 0600 "$cookie_file"
csrf_token=$(curl --fail --silent --show-error --max-time 5 -c "$cookie_file" "${TARGET}/api/auth/csrf" | jq -er '.token')
for count in $(seq 1 6); do
  request -b "$cookie_file" -H "X-XSRF-TOKEN: ${csrf_token}" -H 'Content-Type: application/json' \
    --data '{"username":"synthetic-lab-user","password":"not-the-demo-password"}' "${TARGET}/api/auth/login"
done

# Encoded query/path signals: SQLi, XSS, traversal and scanner User-Agent.
request "${TARGET}/?q=%27%20union%20select%20lab"
request "${TARGET}/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
request "${TARGET}/%2e%2e%2fetc%2fpasswd"
request -A 'Nikto/2.5 (Flare owned lab)' "${TARGET}/"

printf 'Owned-lab abnormal traffic completed for %s. Inspect Kibana after the configured one-minute rule interval.\n' "$TARGET"
