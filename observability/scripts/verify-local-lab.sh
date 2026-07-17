#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
RUNTIME_DIR="${ROOT_DIR}/observability/runtime"
RESULT_FILE="${RUNTIME_DIR}/verification.json"
WEB_URL=${FLARE_LAB_TARGET:-"http://127.0.0.1:${LOCAL_LAB_WEB_PORT:-8088}"}
export OBSERVABILITY_ROOT_DIR="$ROOT_DIR"
export FILEBEAT_CERTS_DIR="${ROOT_DIR}/.secrets/observability/web"
compose_args=(--env-file "${ROOT_DIR}/.env.e2e.example" --project-name "${COMPOSE_PROJECT_NAME:-flare-local-elk}" --profile observability
  -f "${ROOT_DIR}/docker-compose.yml" -f "${ROOT_DIR}/docker-compose.e2e.yml"
  -f "${ROOT_DIR}/observability/docker-compose.monitor.yml" -f "${ROOT_DIR}/observability/docker-compose.local.yml")
compose() { docker compose "${compose_args[@]}" "$@"; }
install -d -m 0750 "$RUNTIME_DIR"
jq -nc --arg started "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{schema_version:1,stack_version:"9.4.2",synthetic_data_only:true,started_at:$started,checks:[]}' >"$RESULT_FILE"

record() {
  local name=$1 status=$2 detail=$3 tmp="${RESULT_FILE}.tmp"
  jq --arg name "$name" --argjson status "$status" --arg detail "$detail" \
    '.checks += [{name:$name,passed:$status,detail:$detail}]' "$RESULT_FILE" >"$tmp"
  mv "$tmp" "$RESULT_FILE"
}
fail() { record "$1" false "$2"; printf 'FAILED: %s — %s\n' "$1" "$2" >&2; exit 1; }
pass() { record "$1" true "$2"; printf 'PASS: %s\n' "$1"; }

elastic_api() {
  local method=$1 endpoint=$2
  compose exec -T elasticsearch bash -ceu '
    password=$(cat /run/flare-secrets/elasticsearch.password)
    args=(--fail --silent --show-error --cacert /usr/share/elasticsearch/config/certs/ca.crt --user "elastic:${password}" -X "$1")
    if [[ "$1" != GET && "$1" != HEAD ]]; then args+=(-H "Content-Type: application/json" --data-binary @-); fi
    curl "${args[@]}" "https://localhost:9200${2}"
  ' -- "$method" "$endpoint"
}

inject_line() { compose exec -T nginx sh -c 'tee -a /var/log/nginx/access.json.log >/dev/null'; }
event() {
  local trace=$1 ip=$2 status=$3 path=$4 duration=${5:-0.004} ua=${6:-Flare-synthetic-verifier}
  jq -nc --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg trace "$trace" --arg ip "$ip" \
    --argjson status "$status" --arg path "$path" --argjson duration "$duration" --arg ua "$ua" \
    '{"@timestamp":$timestamp,"trace.id":$trace,"source.ip":$ip,"http.request.method":"GET","http.request.bytes":64,"http.response.status_code":$status,"http.response.body.bytes":12,"url.path":$path,"url.query":"","url.original":$path,"user_agent.original":$ua,"event.duration_seconds":$duration,"nginx.upstream.status_code":($status|tostring),"nginx.upstream.response_time":($duration|tostring)}'
}

trace_count() {
  jq -nc --arg trace "$1" '{query:{term:{"trace.id":$trace}}}' | elastic_api POST '/logs-nginx.access-lab/_count' | jq -r '.count'
}
wait_trace() {
  local trace=$1 timeout=${2:-15}
  for _ in $(seq 1 "$timeout"); do [ "$(trace_count "$trace" 2>/dev/null || printf 0)" -ge 1 ] && return 0; sleep 1; done
  return 1
}
get_trace() {
  jq -nc --arg trace "$1" '{size:1,query:{term:{"trace.id":$trace}}}' | elastic_api POST '/logs-nginx.access-lab/_search'
}

# Template, mapping and data-stream lifecycle contract.
mapping=$(elastic_api GET '/logs-nginx.access-lab/_mapping' </dev/null)
printf '%s' "$mapping" | jq -e 'to_entries[0].value.mappings.properties.source.properties.geo.properties.location.type=="geo_point"' >/dev/null || fail mapping 'source.geo.location is not geo_point'
lifecycle_access=$(elastic_api GET '/_data_stream/logs-nginx.access-lab/_lifecycle' </dev/null)
lifecycle_error=$(elastic_api GET '/_data_stream/logs-nginx.parse_error-lab/_lifecycle' </dev/null)
[ "$(printf '%s' "$lifecycle_access" | jq -r '.data_streams[0].lifecycle.data_retention')" = 7d ] || fail lifecycle 'access retention is not 7d'
[ "$(printf '%s' "$lifecycle_error" | jq -r '.data_streams[0].lifecycle.data_retention')" = 3d ] || fail lifecycle 'parse-error retention is not 3d'
pass mapping_lifecycle 'geo_point mapping, access 7d, parse-error 3d'

# A real Nginx request must arrive quickly and ignore a spoofed forwarding IP.
headers=$(mktemp)
trap 'rm -f "$headers"' EXIT
curl --fail --silent --show-error -D "$headers" -o /dev/null -H 'X-Forwarded-For: 8.8.8.8' "${WEB_URL}/api/health?token=synthetic-secret-marker"
trace=$(awk 'BEGIN{IGNORECASE=1} /^X-Request-ID:/ {gsub("\r", "", $2); print $2}' "$headers" | tail -n 1)
[ -n "$trace" ] || fail pipeline_latency 'missing X-Request-ID response header'
wait_trace "$trace" 15 || fail pipeline_latency 'request did not arrive within 15 seconds'
doc=$(get_trace "$trace")
printf '%s' "$doc" | jq -e '.hits.hits[0]._source.source.ip != "8.8.8.8" and .hits.hits[0]._source.url.query=="[REDACTED]" and (tostring|contains("synthetic-secret-marker")|not) and (.hits.hits[0]._source|has("body")|not)' >/dev/null || fail redaction_proxy 'spoofed XFF or query/body leakage detected'
pass pipeline_latency_redaction 'arrival <=15s, XFF ignored, query redacted and body absent'

# Public GeoIP and explicit reserved CIDR classification.
public_trace="verify-public-$(date +%s)"
event "$public_trace" 81.2.69.142 200 /geo-public | inject_line
wait_trace "$public_trace" 20 || fail geoip 'public fixture did not arrive'
get_trace "$public_trace" | jq -e '.hits.hits[0]._source.source.geo.location != null and (.hits.hits[0]._source.source.geo.city_name | length > 0) and .hits.hits[0]._source.source.as.number != null' >/dev/null || fail geoip 'public IP lacks City name, geo-point or ASN'
reserved_trace="verify-reserved-$(date +%s)"
event "$reserved_trace" 203.0.113.10 200 /geo-reserved | inject_line
wait_trace "$reserved_trace" || fail cidr_scope 'reserved fixture did not arrive'
get_trace "$reserved_trace" | jq -e '.hits.hits[0]._source.flare.source_ip_scope=="test_net" and (.hits.hits[0]._source.source.geo.location==null)' >/dev/null || fail cidr_scope 'TEST-NET classification or GeoIP exclusion failed'
pass geoip_scope 'public City/ASN enrichment and TEST-NET exclusion verified'

# Malformed typed event routes to the parse-error stream with a reason.
bad_trace="verify-bad-$(date +%s)"
event "$bad_trace" 127.0.0.1 '"not-a-status"' /malformed '"not-a-duration"' |
  jq -c '.["@timestamp"]="not-an-iso-timestamp"' | inject_line
for _ in $(seq 1 30); do
  bad=$(jq -nc --arg trace "$bad_trace" '{size:1,query:{bool:{should:[{term:{"trace.id":$trace}},{term:{"trace.id.keyword":$trace}}],minimum_should_match:1}}}' | elastic_api POST '/logs-nginx.parse_error-lab/_search' 2>/dev/null || true)
  [ "$(printf '%s' "$bad" | jq -r '.hits.total.value // 0' 2>/dev/null || printf 0)" -ge 1 ] && break
  sleep 1
done
printf '%s' "$bad" | jq -e '(.hits.hits[0]._source.flare.parse_error_reason | contains("@timestamp is not ISO-8601")) and (.hits.hits[0]._source.flare.original_timestamp=="not-an-iso-timestamp")' >/dev/null || fail parse_error 'malformed timestamp/numeric event was not quarantined with its original timestamp and reason'
pass parse_error 'malformed timestamp and numeric fields were quarantined with a reason'

# trace.id is the access document ID, so retrying cannot duplicate a document.
duplicate_trace="verify-duplicate-$(date +%s)"
line=$(event "$duplicate_trace" 127.0.0.1 200 /duplicate)
printf '%s\n%s\n' "$line" "$line" | inject_line
wait_trace "$duplicate_trace" || fail deduplication 'duplicate fixture did not arrive'
sleep 2
[ "$(trace_count "$duplicate_trace")" -eq 1 ] || fail deduplication 'same trace.id created more than one document'
pass deduplication 'two deliveries with the same trace.id produced one document'

# Filebeat disk queue survives a Logstash outage; restart remains idempotent.
compose stop logstash >/dev/null
queue_prefix="verify-queue-$(date +%s)"
for number in $(seq 1 5); do event "${queue_prefix}-${number}" 127.0.0.1 200 /queued | inject_line; done
sleep 3
compose start logstash >/dev/null
for number in $(seq 1 5); do wait_trace "${queue_prefix}-${number}" 30 || fail filebeat_queue "queued event ${number} was not delivered"; done
compose restart logstash >/dev/null
sleep 5
for number in $(seq 1 5); do [ "$(trace_count "${queue_prefix}-${number}")" -eq 1 ] || fail persistent_queue 'restart lost or duplicated an event'; done
compose exec -T filebeat test -d /var/lib/filebeat/diskqueue
compose exec -T logstash test -d /usr/share/logstash/data/queue
pass queue_resilience 'Filebeat outage buffer delivered all events; Logstash restart did not duplicate them'

# Exercise all six rule scenarios with synthetic traffic owned by localhost.
alert_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
for number in $(seq 1 120); do curl --silent --output /dev/null --max-time 5 "${WEB_URL}/?verify_rate=${number}" || true; done
cookie_file=$(mktemp)
chmod 0600 "$cookie_file"
csrf=$(curl --fail --silent --show-error -c "$cookie_file" "${WEB_URL}/api/auth/csrf" | jq -er '.token')
for _ in $(seq 1 6); do
  code=$(curl --silent --output /dev/null --write-out '%{http_code}' -b "$cookie_file" -H "X-XSRF-TOKEN: ${csrf}" \
    -H 'Content-Type: application/json' --data '{"username":"synthetic-verifier","password":"intentionally-wrong"}' \
    "${WEB_URL}/api/auth/login")
  [ "$code" = 401 ] || [ "$code" = 429 ] || fail auth_fixture "CSRF-valid login fixture returned ${code}"
done
rm -f "$cookie_file"
for number in $(seq 1 25); do curl --silent --output /dev/null --max-time 5 "${WEB_URL}/api/lab-missing-${number}" || true; done
LOCAL_FIXTURE_CONFIRM=yes "${ROOT_DIR}/observability/scripts/replay-5xx-fixture.sh" >/dev/null
curl --silent --output /dev/null --path-as-is "${WEB_URL}/?q=%27%20union%20select%20synthetic" || true
curl --silent --output /dev/null --path-as-is "${WEB_URL}/?q=%3Cscript%3Esynthetic%3C%2Fscript%3E" || true
curl --silent --output /dev/null --path-as-is "${WEB_URL}/%2e%2e%2fsynthetic" || true
curl --silent --output /dev/null -A 'Nikto synthetic verifier' "${WEB_URL}/" || true

expected_rules='["flare-lab-auth-bruteforce","flare-lab-high-request-rate","flare-lab-high-web-heuristic","flare-lab-scanner-user-agent","flare-lab-server-errors","flare-lab-web-scan-404"]'
alerts=''
for _ in $(seq 1 42); do
  alerts=$(jq -nc --arg start "$alert_start" '{size:0,query:{range:{"@timestamp":{gte:$start}}},aggs:{rules:{terms:{field:"kibana.alert.rule.rule_id",size:20}}}}' |
    elastic_api POST '/.alerts-security.alerts-flare-lab/_search' 2>/dev/null || true)
  if printf '%s' "$alerts" | jq -e --argjson expected "$expected_rules" '([.aggregations.rules.buckets[].key]|sort) as $seen | all($expected[]; $seen|index(.)!=null)' >/dev/null 2>&1; then break; fi
  sleep 5
done
printf '%s' "$alerts" | jq -e --argjson expected "$expected_rules" '([.aggregations.rules.buckets[].key]|sort) as $seen | all($expected[]; $seen|index(.)!=null)' >/dev/null || fail detection_alerts 'not all six detection rules produced an alert within 210 seconds'
pass detection_alerts 'all six rule IDs produced alerts from localhost synthetic scenarios'

# Import twice to prove stable IDs/overwrite behavior, then validate dashboards/rules.
"${ROOT_DIR}/observability/scripts/setup-kibana.sh" >/dev/null
"${ROOT_DIR}/observability/scripts/setup-kibana.sh" >/dev/null
pass kibana_import 'saved objects and six rules imported twice with overwrite'

# Analyst has read-only application privileges and no management/write grants.
role=$(elastic_api GET '/_security/role/flare_analyst' </dev/null)
printf '%s' "$role" | jq -e '.flare_analyst.cluster==[] and ([.flare_analyst.indices[].privileges[]]|all(.=="read" or .=="view_index_metadata")) and ([.flare_analyst.applications[].privileges[]]|all(endswith(".read")))' >/dev/null || fail analyst_role 'role contains a write, management or non-read application privilege'
analyst_password=$(<"${ROOT_DIR}/.secrets/observability/monitor/analyst.password")
for dashboard in flare-overview flare-geoip flare-security; do
  code=$(curl --silent --output /dev/null --write-out '%{http_code}' --config <(printf 'user = "flare_analyst:%s"\n' "$analyst_password") "http://127.0.0.1:5601/s/flare-lab/api/saved_objects/dashboard/${dashboard}")
  [ "$code" = 200 ] || fail analyst_role "analyst cannot read ${dashboard} (HTTP ${code})"
done
pass analyst_role 'analyst can read all dashboards; role exposes only read privileges'

# Runtime surface: Elasticsearch is private and raw observability passwords are
# absent from all three container environment arrays.
for service in elasticsearch logstash kibana; do
  id=$(compose ps -q "$service")
  env=$(docker inspect "$id" --format '{{json .Config.Env}}')
  for password_file in "${ROOT_DIR}/.secrets/observability/monitor/"*.password; do
    secret=$(<"$password_file")
    printf '%s' "$env" | grep -F "$secret" >/dev/null && fail container_secrets "raw secret found in ${service} environment"
  done
done
es_id=$(compose ps -q elasticsearch)
bindings=$(docker inspect "$es_id" --format '{{json .HostConfig.PortBindings}}')
printf '%s' "$bindings" | jq -e '(. // {}) | has("9200/tcp")|not' >/dev/null || fail private_ports 'Elasticsearch 9200 is published'
printf '%s' "$bindings" | jq -e '(. // {}) | has("9300/tcp")|not' >/dev/null || fail private_ports 'Elasticsearch 9300 is published'
pass container_secrets_ports 'no raw observability secret in inspect; 9200/9300 unpublished'

tmp="${RESULT_FILE}.tmp"
jq --arg finished "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.finished_at=$finished | .passed=all(.checks[];.passed)' "$RESULT_FILE" >"$tmp"
mv "$tmp" "$RESULT_FILE"
printf 'Machine-readable verification: %s\n' "$RESULT_FILE"
