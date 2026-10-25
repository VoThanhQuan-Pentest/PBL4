#!/usr/bin/env bash
set -Eeuo pipefail

# Non-destructive AWS smoke gate. Authenticated checks create/revoke sessions.
# It verifies a previously applied/deployed lab
# and writes sanitized JSON/Markdown evidence under the ignored runtime folder.
# It never runs terraform apply/destroy and never copies a password into output.
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
: "${WEB_HOST:?Set WEB_HOST, for example ubuntu@203.0.113.10}"
: "${MONITOR_HOST:?Set MONITOR_HOST, for example ubuntu@203.0.113.20}"
: "${FLARE_LAB_TARGET:?Set FLARE_LAB_TARGET to the group-owned Web origin}"
: "${FLARE_LAB_ALLOWED_HOST:?Set FLARE_LAB_ALLOWED_HOST to the Web EIP host}"
[ "${I_OWN_THIS_TARGET:-}" = "yes" ] || { printf 'Set I_OWN_THIS_TARGET=yes after confirming ownership.\n' >&2; exit 1; }

for host in "$WEB_HOST" "$MONITOR_HOST"; do
  [[ "$host" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$ ]] || {
    printf 'SSH hosts must be explicit user@IPv4-or-hostname targets.\n' >&2
    exit 1
  }
done
TARGET=${FLARE_LAB_TARGET%/}
[[ "$TARGET" =~ ^https?://([A-Za-z0-9.-]+)(:[0-9]{1,5})?$ ]] || {
  printf 'FLARE_LAB_TARGET must be one HTTP(S) origin without a path, query or userinfo.\n' >&2
  exit 1
}
target_host=${BASH_REMATCH[1]}
[ "$target_host" = "$FLARE_LAB_ALLOWED_HOST" ] || { printf 'Target host is not the explicit allowlist host.\n' >&2; exit 1; }
for binary in curl jq ssh terraform; do
  command -v "$binary" >/dev/null 2>&1 || { printf 'Missing required command: %s\n' "$binary" >&2; exit 1; }
done

SSH_OPTIONS=${SSH_OPTIONS:-"-o BatchMode=yes -o StrictHostKeyChecking=accept-new"}
read -r -a ssh_options <<<"$SSH_OPTIONS"
run_id=$(date -u +%Y%m%dT%H%M%SZ)
DEST=${AWS_EVIDENCE_DIR:-"${ROOT_DIR}/observability/runtime/aws-evidence-${run_id}"}
if [ -e "$DEST" ] && [ -n "$(find "$DEST" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
  printf 'Refusing to overwrite a non-empty evidence directory: %s\n' "$DEST" >&2
  exit 1
fi
umask 077
install -d -m 0700 "$DEST"
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

header_file=$(mktemp)
trap 'rm -f "$header_file"' EXIT
website_status=$(curl --silent --show-error --max-time 15 --dump-header "$header_file" --output /dev/null --write-out '%{http_code}' "${TARGET}/api/health")
[ "$website_status" = 200 ] || { printf 'Website health check returned HTTP %s.\n' "$website_status" >&2; exit 1; }
probe_trace_id=$(awk 'BEGIN { IGNORECASE=1 } $1 == "X-Request-ID:" { gsub("\\r", "", $2); value=$2 } END { print value }' "$header_file")
[[ "$probe_trace_id" =~ ^[a-fA-F0-9]{32}$ ]] || { printf 'Website health response did not contain a valid X-Request-ID.\n' >&2; exit 1; }
terraform -chdir="${ROOT_DIR}/terraform" output -json |
  jq 'with_entries(select(.value.sensitive != true))' >"${DEST}/terraform-outputs.json"

ssh "${ssh_options[@]}" "$WEB_HOST" 'bash -se' >"${DEST}/web-runtime.json" <<'WEB_REMOTE'
set -Eeuo pipefail
cd /opt/flare
compose=(/opt/flare/observability/scripts/aws-compose.sh web --profile observability)
cloud_init=$(sudo cloud-init status --wait)
services=$("${compose[@]}" ps --format json | jq -sc '
  (if length == 1 and (.[0] | type) == "array" then .[0] else . end) |
  map({service:.Service,state:.State,health:(.Health // "")})')
filebeat_output=false
# This remote block is supplied through stdin. Prevent `docker compose exec`
# from consuming the rest of the heredoc while Filebeat runs its output test.
if "${compose[@]}" exec -T filebeat filebeat test output --strict.perms=false --path.data /tmp/aws-acceptance-output-test </dev/null >/dev/null 2>&1; then
  filebeat_output=true
fi
gateway_healthy=false
if "${compose[@]}" exec -T gateway /prevention-gateway healthcheck </dev/null >/dev/null 2>&1; then
  gateway_healthy=true
fi
recovery_loopback=false
gateway_container=$("${compose[@]}" ps -q gateway)
if [ -n "$gateway_container" ]; then
  recovery_ports=$(docker inspect "$gateway_container" --format '{{json .HostConfig.PortBindings}}')
  if printf '%s' "$recovery_ports" | jq -e '.["8089/tcp"][0].HostIp=="127.0.0.1"' >/dev/null 2>&1; then
    recovery_loopback=true
  fi
fi
jq -nc --arg cloud_init "$cloud_init" --argjson services "$services" --argjson filebeat_output "$filebeat_output" \
  --argjson gateway_healthy "$gateway_healthy" --argjson recovery_loopback "$recovery_loopback" \
  '{cloud_init:$cloud_init,services:$services,filebeat_output:$filebeat_output,gateway_healthy:$gateway_healthy,recovery_loopback:$recovery_loopback}'
WEB_REMOTE

ssh "${ssh_options[@]}" "$MONITOR_HOST" bash -se -- "$probe_trace_id" >"${DEST}/monitor-runtime.json" <<'MONITOR_REMOTE'
set -Eeuo pipefail
probe_trace_id=$1
cd /opt/flare
compose=(/opt/flare/observability/scripts/aws-compose.sh monitor)
cloud_init=$(sudo cloud-init status --wait)
services=$("${compose[@]}" ps --format json | jq -sc '
  (if length == 1 and (.[0] | type) == "array" then .[0] else . end) |
  map({service:.Service,state:.State,health:(.Health // "")})')
mount_ready=false
mountpoint -q /srv/elastic && mount_ready=true

elastic_api() {
  local endpoint=$1 body=${2:-}
  # The Monitor acceptance block also arrives over stdin, so each exec must
  # explicitly detach stdin before Elasticsearch commands are issued.
  "${compose[@]}" exec -T elasticsearch bash -ceu '
    endpoint=$1
    body=$2
    password=$(cat /run/flare-secrets/elasticsearch.password)
    args=(--fail --silent --show-error --cacert /usr/share/elasticsearch/config/certs/ca.crt --user "elastic:${password}")
    if [ -n "$body" ]; then
      args+=(-H "Content-Type: application/json" --data-binary "$body")
    fi
    curl "${args[@]}" "https://localhost:9200${endpoint}"
  ' -- "$endpoint" "$body" </dev/null
}

cluster=$(elastic_api '/_cluster/health')
access_query=$(jq -nc --arg trace "$probe_trace_id" '{size:0,track_total_hits:true,query:{term:{"trace.id":$trace}},aggs:{public_geo:{filter:{exists:{field:"source.geo.location"}}}}}')
access=''
for attempt in $(seq 1 30); do
  access=$(elastic_api '/logs-nginx.access-lab/_search' "$access_query")
  if printf '%s' "$access" | jq -e '.hits.total.value > 0 and .aggregations.public_geo.doc_count > 0' >/dev/null; then
    break
  fi
  [ "$attempt" -eq 30 ] || sleep 1
done
alerts=$(elastic_api '/.alerts-security.alerts-flare-lab/_search' '{"size":0,"aggs":{"rules":{"terms":{"field":"kibana.alert.rule.rule_id","size":20}}}}')

elastic_password=$(<.secrets/observability/monitor/elasticsearch.password)
kibana_curl() {
  curl --fail --silent --show-error --config <(printf 'user = "elastic:%s"\n' "$elastic_password") \
    -H 'kbn-xsrf: flare-aws-acceptance' "$@"
}
dashboards=$(kibana_curl 'http://127.0.0.1:5601/s/flare-lab/api/saved_objects/_find?type=dashboard&per_page=100')
rules=$(kibana_curl -H 'Elastic-Api-Version: 2023-10-31' \
  'http://127.0.0.1:5601/s/flare-lab/api/detection_engine/rules/_find?per_page=100')

jq -nc \
  --arg cloud_init "$cloud_init" \
  --arg trace "$probe_trace_id" \
  --argjson services "$services" \
  --argjson mount_ready "$mount_ready" \
  --argjson cluster "$cluster" \
  --argjson access "$access" \
  --argjson alerts "$alerts" \
  --argjson dashboards "$dashboards" \
  --argjson rules "$rules" \
  '{
    cloud_init:$cloud_init,
    probe_trace_id:$trace,
    services:$services,
    elasticsearch_data_mount:$mount_ready,
    cluster_status:$cluster.status,
    access_documents:$access.hits.total.value,
    public_geo_documents:$access.aggregations.public_geo.doc_count,
    alert_rule_ids:([$alerts.aggregations.rules.buckets[].key] | sort),
    dashboard_count:([$dashboards.saved_objects[] | select(.id=="flare-overview" or .id=="flare-geoip" or .id=="flare-security")] | length),
    detection_rule_count:([$rules.data[] | select(.rule_id | startswith("flare-lab-"))] | length)
  }'
MONITOR_REMOTE

ssh "${ssh_options[@]}" "$WEB_HOST" 'cd /opt/flare && python3 observability/scripts/aws-soc.py verify --url http://127.0.0.1:8089 --credentials observability/runtime/private-credentials/aws-operators.json' >"${DEST}/soc-runtime.json"
jq -e '.passed == true and .rbac == true' "${DEST}/soc-runtime.json" >/dev/null

expected_services_web='["app","db","filebeat","gateway","nginx","redis","ueba-worker"]'
expected_services_monitor='["elasticsearch","kibana","logstash"]'
expected_alerts='["flare-lab-auth-bruteforce","flare-lab-high-request-rate","flare-lab-high-web-heuristic","flare-lab-scanner-user-agent","flare-lab-server-errors","flare-lab-web-scan-404"]'

jq -e --argjson expected "$expected_services_web" '
  (.cloud_init | test("done"; "i")) and
  .filebeat_output == true and
  .gateway_healthy == true and .recovery_loopback == true and
  (([.services[] | select(.state=="running") | .service] | sort) as $running |
    (($expected - $running) | length) == 0)
' "${DEST}/web-runtime.json" >/dev/null
jq -e --argjson expected_services "$expected_services_monitor" --argjson expected_alerts "$expected_alerts" '
  (.cloud_init | test("done"; "i")) and .elasticsearch_data_mount == true and
  (.cluster_status=="green" or .cluster_status=="yellow") and
  .access_documents > 0 and .public_geo_documents > 0 and
  .dashboard_count == 3 and .detection_rule_count == 6 and
  (.alert_rule_ids == $expected_alerts) and
  (([.services[] | select(.state=="running") | .service] | sort) as $running |
    (($expected_services - $running) | length) == 0)
' "${DEST}/monitor-runtime.json" >/dev/null

finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
git_commit=$(git -C "$ROOT_DIR" rev-parse HEAD)
jq -n \
  --arg started_at "$started_at" \
  --arg finished_at "$finished_at" \
  --arg git_commit "$git_commit" \
  --arg target "$TARGET" \
  --arg trace "$probe_trace_id" \
  --argjson website_status "$website_status" \
  --slurpfile web "${DEST}/web-runtime.json" \
  --slurpfile monitor "${DEST}/monitor-runtime.json" \
  --slurpfile soc "${DEST}/soc-runtime.json" \
  '{passed:true,scope:"aws-runtime-smoke",full_acceptance:false,synthetic_data_only:false,started_at:$started_at,finished_at:$finished_at,git_commit:$git_commit,target:$target,probe_trace_id:$trace,website_http_status:$website_status,web:$web[0],monitor:$monitor[0],soc:$soc[0]}' \
  >"${DEST}/verification.json"

# Backticks below are literal Markdown, not command substitutions.
# shellcheck disable=SC2016
{
  printf '# Flare AWS lab verification\n\n'
  printf -- '- Result: **PASS**\n'
  printf -- '- Scope: deployed AWS runtime; no credential is included.\n'
  printf -- '- Commit: `%s`\n' "$git_commit"
  printf -- '- Target: `%s`\n' "$TARGET"
  printf -- '- Started: `%s`\n' "$started_at"
  printf -- '- Finished: `%s`\n\n' "$finished_at"
  printf '## Automated checks\n\n'
  printf -- '- [x] Website health returned HTTP 200.\n'
  printf -- '- [x] Web and Monitor cloud-init completed.\n'
  printf -- '- [x] Required containers are running and Filebeat mTLS output succeeds.\n'
  printf -- '- [x] Elasticsearch EBS mount and cluster health are ready.\n'
  printf -- '- [x] The exact health probe trace reached Elasticsearch with public GeoIP.\n'
  printf -- '- [x] Three dashboards, six rules and all six alert IDs exist.\n\n'
  printf -- '- [x] SOC roles, active DEMO_ONLY model and applied gateway policy pass API checks.\n'
  printf -- '- [ ] Complete the separate workflow, 30-sample latency and recovery acceptance matrix.\n\n'
  printf 'Attach AWS Console and Kibana screenshots separately; never add passwords, private keys, cookies, JWTs or raw `.env` files.\n'
} >"${DEST}/verification.md"

printf 'AWS runtime verification passed. Sanitized evidence: %s\n' "$DEST"
