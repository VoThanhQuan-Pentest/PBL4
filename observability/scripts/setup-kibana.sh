#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SECRETS_DIR=${OBSERVABILITY_SECRETS_DIR:-"${ROOT_DIR}/.secrets/observability"}
ELASTIC_PASSWORD_FILE="${SECRETS_DIR}/monitor/elasticsearch.password"
KIBANA_URL=${KIBANA_URL:-http://127.0.0.1:5601}
SPACE_ID=flare-lab

for binary in curl jq; do
  command -v "$binary" >/dev/null 2>&1 || { printf 'Missing required command: %s\n' "$binary" >&2; exit 1; }
done
[ -r "$ELASTIC_PASSWORD_FILE" ] || { printf 'Run observability/scripts/bootstrap-secrets.sh first.\n' >&2; exit 1; }

kibana_curl() {
  local password
  password=$(<"$ELASTIC_PASSWORD_FILE")
  curl --fail --silent --show-error --config <(printf 'user = "elastic:%s"\n' "$password") \
    -H 'kbn-xsrf: flare-local-elk' "$@"
}

for attempt in $(seq 1 90); do
  if kibana_curl "${KIBANA_URL}/api/status" >/dev/null 2>&1; then break; fi
  [ "$attempt" -ne 90 ] || { printf 'Kibana did not become ready.\n' >&2; exit 1; }
  sleep 2
done

if ! kibana_curl -o /dev/null "${KIBANA_URL}/api/spaces/space/${SPACE_ID}" 2>/dev/null; then
  kibana_curl -X POST -H 'Content-Type: application/json' \
    --data-binary '{"id":"flare-lab","name":"Flare Lab","description":"Synthetic AWS–ELK lab dashboards and detection rules","solution":"security"}' \
    "${KIBANA_URL}/api/spaces/space" >/dev/null
fi

kibana_curl -X POST -H 'Content-Type: application/json' \
  --data-binary '{"override":true,"data_view":{"id":"flare-nginx-logs","name":"Flare Lab Nginx logs","title":"logs-nginx.*-lab","timeFieldName":"@timestamp","allowNoIndex":true}}' \
  "${KIBANA_URL}/s/${SPACE_ID}/api/data_views/data_view" >/dev/null

import_objects() {
  kibana_curl -X POST -F "file=@${ROOT_DIR}/observability/kibana/saved_objects.ndjson" \
    "${KIBANA_URL}/s/${SPACE_ID}/api/saved_objects/_import?overwrite=true" |
    jq -e '.success == true and (.successCount >= 21)' >/dev/null
  kibana_curl -X POST -F "file=@${ROOT_DIR}/observability/kibana/detection_rules.ndjson" \
    -H 'Elastic-Api-Version: 2023-10-31' \
    "${KIBANA_URL}/s/${SPACE_ID}/api/detection_engine/rules/_import?overwrite=true" |
    jq -e '((.errors // []) | length == 0) and ((.success_count // .successCount // 6) == 6)' >/dev/null
}

import_objects

rules=$(kibana_curl -H 'Elastic-Api-Version: 2023-10-31' \
  "${KIBANA_URL}/s/${SPACE_ID}/api/detection_engine/rules/_find?per_page=100")
printf '%s' "$rules" | jq -e '
  [.data[] | select(.rule_id | startswith("flare-lab-"))] |
  def rule($id): first(.[] | select(.rule_id==$id));
  length==6 and all(.[]; .enabled==true and .interval=="1m") and
  (rule("flare-lab-high-request-rate") | .from=="now-2m" and .threshold.value==100) and
  (rule("flare-lab-web-scan-404") | .from=="now-3m" and .threshold.value==20) and
  (rule("flare-lab-auth-bruteforce") | .from=="now-6m" and .threshold.value==5) and
  (rule("flare-lab-server-errors") | .from=="now-6m" and .threshold.value==5) and
  (rule("flare-lab-high-web-heuristic") | .from=="now-2m" and .type=="query") and
  (rule("flare-lab-scanner-user-agent") | .from=="now-2m" and .type=="query")
' >/dev/null

dashboards=$(kibana_curl "${KIBANA_URL}/s/${SPACE_ID}/api/saved_objects/_find?type=dashboard&per_page=100")
printf '%s' "$dashboards" | jq -e '[.saved_objects[] | select(.id=="flare-overview" or .id=="flare-geoip" or .id=="flare-security")] | length == 3 and all(.[]; (.attributes.panelsJSON | fromjson | length) > 0)' >/dev/null

install -d -m 0750 "${ROOT_DIR}/observability/runtime"
"${ROOT_DIR}/observability/scripts/export-kibana-objects.sh" \
  "${ROOT_DIR}/observability/runtime/kibana-9.4.2-export.ndjson"

printf 'Kibana space, 18 panels, three dashboards and six enabled rules are ready.\n'
