#!/usr/bin/env bash
set -Eeuo pipefail

# Bootstrap Elasticsearch through its private Compose network. Port 9200 stays
# unpublished; credentials are read from mounted files and request stdin.
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SECRETS_DIR=${OBSERVABILITY_SECRETS_DIR:-"${ROOT_DIR}/.secrets/observability"}
MONITOR_DIR="${SECRETS_DIR}/monitor"

for binary in docker jq; do
  command -v "$binary" >/dev/null 2>&1 || { printf 'Missing required command: %s\n' "$binary" >&2; exit 1; }
done
for path in elasticsearch.password kibana-system.password logstash-internal.password analyst.password; do
  [ -r "${MONITOR_DIR}/${path}" ] || { printf 'Run observability/scripts/bootstrap-secrets.sh first.\n' >&2; exit 1; }
done

compose_args=()
if [ -n "${OBSERVABILITY_COMPOSE_FILES:-}" ]; then
  IFS=: read -r -a compose_files <<<"$OBSERVABILITY_COMPOSE_FILES"
  for file in "${compose_files[@]}"; do compose_args+=(-f "$file"); done
else
  compose_args=(-f "${ROOT_DIR}/observability/docker-compose.monitor.yml")
fi
if [ -n "${OBSERVABILITY_COMPOSE_ENV_FILE:-}" ]; then
  compose_args=(--env-file "$OBSERVABILITY_COMPOSE_ENV_FILE" "${compose_args[@]}")
fi
compose() { docker compose "${compose_args[@]}" "$@"; }

elastic_api() {
  local method=$1 endpoint=$2
  compose exec -T elasticsearch bash -ceu '
    method=$1
    endpoint=$2
    password=$(cat /run/flare-secrets/elasticsearch.password)
    args=(--fail --silent --show-error --cacert /usr/share/elasticsearch/config/certs/ca.crt --user "elastic:${password}" -X "$method")
    if [[ "$method" != GET && "$method" != HEAD ]]; then
      args+=(-H "Content-Type: application/json" --data-binary @-)
    fi
    curl "${args[@]}" "https://localhost:9200${endpoint}"
  ' -- "$method" "$endpoint"
}

wait_for_elasticsearch() {
  for attempt in $(seq 1 60); do
    if elastic_api GET '/_cluster/health?wait_for_status=yellow&timeout=1s' </dev/null >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  printf 'Elasticsearch did not become ready inside Compose.\n' >&2
  return 1
}

put_file() {
  elastic_api PUT "$1" <"$2" >/dev/null
}

ensure_data_stream() {
  local name=$1
  elastic_api GET "/_data_stream/${name}" </dev/null >/dev/null 2>&1 || \
    elastic_api PUT "/_data_stream/${name}" </dev/null >/dev/null
}

wait_for_elasticsearch
put_file '/_index_template/flare-nginx-access' "${ROOT_DIR}/observability/elasticsearch/templates/nginx-access.json"
put_file '/_index_template/flare-nginx-parse-error' "${ROOT_DIR}/observability/elasticsearch/templates/nginx-parse-error.json"

jq -nc '{cluster:["monitor"],indices:[{names:["logs-nginx.access-lab","logs-nginx.parse_error-lab"],privileges:["auto_configure","create_doc"]}],applications:[],run_as:[],metadata:{description:"Logstash health monitoring plus write-only access to Flare lab streams"}}' |
  elastic_api PUT '/_security/role/flare_ingest' >/dev/null
jq -nc '{cluster:[],indices:[{names:["logs-nginx.access-lab","logs-nginx.parse_error-lab",".alerts-security.alerts-flare-lab",".internal.alerts-security.alerts-flare-lab-*"],privileges:["read","view_index_metadata"]}],applications:[{application:"kibana-.kibana",privileges:["feature_discover.read","feature_dashboard.read","feature_maps.read","feature_securitySolution.read"],resources:["space:flare-lab"]}],run_as:[],metadata:{description:"Read-only Flare Lab analyst for Discover, dashboards, maps and security alerts"}}' |
  elastic_api PUT '/_security/role/flare_analyst' >/dev/null

jq -Rrs 'rtrimstr("\n") | {password:.,roles:["flare_ingest"],full_name:"Flare Logstash ingest"}' <"${MONITOR_DIR}/logstash-internal.password" |
  elastic_api PUT '/_security/user/logstash_internal' >/dev/null
jq -Rrs 'rtrimstr("\n") | {password:.,roles:["flare_analyst"],full_name:"Flare Lab analyst"}' <"${MONITOR_DIR}/analyst.password" |
  elastic_api PUT '/_security/user/flare_analyst' >/dev/null
jq -Rrs 'rtrimstr("\n") | {password:.}' <"${MONITOR_DIR}/kibana-system.password" |
  elastic_api POST '/_security/user/kibana_system/_password' >/dev/null

ensure_data_stream logs-nginx.access-lab
ensure_data_stream logs-nginx.parse_error-lab
printf '%s' '{"data_retention":"7d"}' | elastic_api PUT '/_data_stream/logs-nginx.access-lab/_lifecycle' >/dev/null
printf '%s' '{"data_retention":"3d"}' | elastic_api PUT '/_data_stream/logs-nginx.parse_error-lab/_lifecycle' >/dev/null

printf 'Elasticsearch templates, retention and least-privilege users are ready.\n'
