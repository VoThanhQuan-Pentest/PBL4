#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SECRETS_DIR=${OBSERVABILITY_SECRETS_DIR:-"${ROOT_DIR}/.secrets/observability"}
PASSWORD_FILE="${SECRETS_DIR}/monitor/elasticsearch.password"
KIBANA_URL=${KIBANA_URL:-http://127.0.0.1:5601}
[[ "$KIBANA_URL" =~ ^http://(127\.0\.0\.1|localhost):[0-9]{1,5}$ ]] || {
  printf 'Kibana pre-import backup requires an exact loopback HTTP origin.\n' >&2
  exit 2
}
[ -r "$PASSWORD_FILE" ] || { printf 'Missing local Kibana backup credential.\n' >&2; exit 1; }
for binary in curl jq; do
  command -v "$binary" >/dev/null || { printf 'Missing required command: %s\n' "$binary" >&2; exit 1; }
done

kibana_curl() {
  local password
  password=$(<"$PASSWORD_FILE")
  curl --silent --show-error --config <(printf 'user = "elastic:%s"\n' "$password") \
    -H 'kbn-xsrf: flare-local-elk' "$@"
}

space_status=$(kibana_curl -o /dev/null -w '%{http_code}' \
  "${KIBANA_URL}/api/spaces/space/flare-lab")
case "$space_status" in
  404) printf 'Flare Kibana space does not exist yet; no pre-import backup needed.\n'; exit 0 ;;
  200) ;;
  *) printf 'Cannot verify existing Kibana space (HTTP %s); refusing overwrite.\n' "$space_status" >&2; exit 1 ;;
esac

umask 077
backup_root=${KIBANA_BACKUP_ROOT:-"${ROOT_DIR}/observability/runtime/private-backups"}
backup_root=$(realpath -m -- "$backup_root")
case "$backup_root" in
  "${ROOT_DIR}/observability/runtime/"*) ;;
  *) printf 'Kibana backup output must stay under observability/runtime.\n' >&2; exit 2 ;;
esac
install -d -m 0700 "$backup_root"
backup_dir=$(mktemp -d "${backup_root}/kibana-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
"${ROOT_DIR}/observability/scripts/export-kibana-objects.sh" \
  "${backup_dir}/saved-objects.ndjson"

rules=$(kibana_curl -H 'Elastic-Api-Version: 2023-10-31' \
  "${KIBANA_URL}/s/flare-lab/api/detection_engine/rules/_find?per_page=1000")
printf '%s' "$rules" | jq -e '(.total | type == "number") and (.data | type == "array") and (.total == (.data | length))' >/dev/null || {
  printf 'Detection-rule listing is incomplete; refusing overwrite.\n' >&2
  exit 1
}
rule_count=$(printf '%s' "$rules" | jq -r '.total')
request=$(printf '%s' "$rules" | jq -c '{objects:[.data[] | {rule_id}]}')
kibana_curl --fail -H 'Elastic-Api-Version: 2023-10-31' \
  -H 'Content-Type: application/json' -X POST --data-binary "$request" \
  "${KIBANA_URL}/s/flare-lab/api/detection_engine/rules/_export" \
  >"${backup_dir}/detection-rules.ndjson"
jq -s -e --argjson expected "$rule_count" \
  '([.[] | select(.rule_id != null)] | length) == $expected' \
  "${backup_dir}/detection-rules.ndjson" >/dev/null || {
  printf 'Detection-rule export is incomplete; refusing overwrite.\n' >&2
  exit 1
}
chmod 0600 "${backup_dir}/saved-objects.ndjson" "${backup_dir}/detection-rules.ndjson"
printf 'Existing Kibana dashboards and %s rules backed up privately to %s\n' "$rule_count" "$backup_dir"
printf 'Do not upload these files as public report evidence.\n'
