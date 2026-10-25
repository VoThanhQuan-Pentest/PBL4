#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
compose() { "$ROOT_DIR/observability/scripts/aws-compose.sh" web "$@"; }
# Values are expanded only inside the container; no credential is printed.
# shellcheck disable=SC2016
compose exec -T app sh -ceu '
  for file in siem-ca.crt siem-reader.password ueba.token prevention.token; do
    test -f "/run/flare-secrets/$file" && test -r "/run/flare-secrets/$file"
  done
  reader_password=$(cat /run/flare-secrets/siem-reader.password)
  curl --fail --silent --show-error --max-time 8 --cacert /run/flare-secrets/siem-ca.crt \
    --user "flare_siem_reader:$reader_password" \
    https://10.20.10.20:9200/logs-nginx.access-lab/_count >/dev/null
  curl --fail --silent --show-error --max-time 5 http://ueba-worker:8091/health >/dev/null
'
gateway=$(curl --fail --silent --show-error --max-time 5 http://127.0.0.1/healthz)
printf '%s' "$gateway" | jq -e '.status=="UP" and .redis_state=="UP"' >/dev/null
curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8089/api/health | jq -e '.status=="UP"' >/dev/null
compose exec -T filebeat filebeat test output --strict.perms=false --path.data /tmp/aws-readiness >/dev/null
printf 'READY: gateway, Redis, recovery API, SIEM reader TLS, UEBA and Filebeat.\n'
