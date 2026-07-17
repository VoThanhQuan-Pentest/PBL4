#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SECRETS_DIR=${OBSERVABILITY_SECRETS_DIR:-"${ROOT_DIR}/.secrets/observability"}
PASSWORD_FILE="${SECRETS_DIR}/monitor/elasticsearch.password"
KIBANA_URL=${KIBANA_URL:-http://127.0.0.1:5601}
OUTPUT=${1:-"${ROOT_DIR}/observability/runtime/kibana-9.4.2-export.ndjson"}
[ -r "$PASSWORD_FILE" ] || { printf 'Missing Elasticsearch password file.\n' >&2; exit 1; }
install -d -m 0750 "$(dirname -- "$OUTPUT")"
tmp="${OUTPUT}.tmp"
trap 'rm -f "$tmp"' EXIT
password=$(<"$PASSWORD_FILE")
curl --fail --silent --show-error --config <(printf 'user = "elastic:%s"\n' "$password") \
  -H 'kbn-xsrf: flare-local-elk' -H 'Content-Type: application/json' -X POST \
  --data-binary '{"objects":[{"type":"dashboard","id":"flare-overview"},{"type":"dashboard","id":"flare-geoip"},{"type":"dashboard","id":"flare-security"}],"includeReferencesDeep":true,"excludeExportDetails":false}' \
  "${KIBANA_URL}/s/flare-lab/api/saved_objects/_export" >"$tmp"
while IFS= read -r line; do printf '%s' "$line" | jq -e . >/dev/null; done <"$tmp"
mv "$tmp" "$OUTPUT"
printf 'Official Kibana saved-object export written to %s\n' "$OUTPUT"
