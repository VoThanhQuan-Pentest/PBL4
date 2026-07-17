#!/usr/bin/env bash
set -Eeuo pipefail

# Generate benign lab traffic. Set FLARE_LAB_TARGET to an HTTP origin belonging
# to the group, e.g. http://<web-eip>. Optional login values are read only from
# the local environment and are never written to a URL or log file.
: "${FLARE_LAB_TARGET:?Set FLARE_LAB_TARGET to the group-owned lab HTTP origin}"
TARGET=${FLARE_LAB_TARGET%/}

curl --fail --silent --show-error --max-time 10 -o /dev/null "${TARGET}/"
curl --fail --silent --show-error --max-time 10 -o /dev/null "${TARGET}/api/products"
curl --fail --silent --show-error --max-time 10 -o /dev/null "${TARGET}/api/health"

if [ -n "${DEMO_LOGIN_EMAIL:-}" ] && [ -n "${DEMO_LOGIN_PASSWORD:-}" ]; then
  curl --silent --show-error --max-time 10 -o /dev/null -c /tmp/flare-lab-cookies.txt \
    -H 'Content-Type: application/json' \
    --data "{\"email\":\"${DEMO_LOGIN_EMAIL}\",\"password\":\"${DEMO_LOGIN_PASSWORD}\"}" \
    "${TARGET}/api/auth/login"
  rm -f /tmp/flare-lab-cookies.txt
fi

printf 'Normal traffic sent to %s\n' "$TARGET"
