#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"
for binary in docker jq; do command -v "$binary" >/dev/null 2>&1 || { printf 'Missing required command: %s\n' "$binary" >&2; exit 1; }; done

find observability/scripts -maxdepth 1 -type f -name '*.sh' -print0 | while IFS= read -r -d '' script; do
  bash -n "$script"
done
find observability/elasticsearch -type f -name '*.json' -print0 | while IFS= read -r -d '' file; do jq -e . "$file" >/dev/null; done
for file in observability/kibana/*.ndjson; do
  [ -s "$file" ] || { printf 'Empty NDJSON file: %s\n' "$file" >&2; exit 1; }
  while IFS= read -r line; do printf '%s' "$line" | jq -e . >/dev/null; done <"$file"
done

jq -s -e '
  [ .[] | select(.type=="dashboard") | {id, panels:(.attributes.panelsJSON|fromjson|length)} ] as $dashboards |
  ($dashboards|length)==3 and
  ([$dashboards[]|select(.id=="flare-overview" and .panels>=8)]|length)==1 and
  ([$dashboards[]|select(.id=="flare-geoip" and .panels>=4)]|length)==1 and
  ([$dashboards[]|select(.id=="flare-security" and .panels>=6)]|length)==1
' observability/kibana/saved_objects.ndjson >/dev/null
jq -s -e '
  def rule($id): first(.[] | select(.rule_id==$id));
  length==6 and ([.[].rule_id]|unique|length)==6 and all(.[]; .enabled==true and .interval=="1m") and
  (rule("flare-lab-high-request-rate") | .type=="threshold" and .from=="now-2m" and .threshold.value==100) and
  (rule("flare-lab-web-scan-404") | .type=="threshold" and .from=="now-3m" and .threshold.value==20) and
  (rule("flare-lab-auth-bruteforce") | .type=="threshold" and .from=="now-6m" and .threshold.value==5) and
  (rule("flare-lab-server-errors") | .type=="threshold" and .from=="now-6m" and .threshold.value==5) and
  (rule("flare-lab-high-web-heuristic") | .type=="query" and .from=="now-2m") and
  (rule("flare-lab-scanner-user-agent") | .type=="query" and .from=="now-2m")
' \
  observability/kibana/detection_rules.ndjson >/dev/null

[ -r .secrets/observability/web/ca.crt ] && [ -r .secrets/observability/monitor/logstash.keystore ] || {
  printf 'Run observability/scripts/bootstrap-secrets.sh before image-native validation.\n' >&2
  exit 1
}

export OBSERVABILITY_ROOT_DIR="$ROOT_DIR"
export FILEBEAT_CERTS_DIR="${ROOT_DIR}/.secrets/observability/web"
compose_args=(--env-file .env.e2e.example --project-name flare-local-elk --profile observability
  -f docker-compose.yml -f docker-compose.e2e.yml
  -f observability/docker-compose.monitor.yml -f observability/docker-compose.local.yml)

rendered=$(docker compose "${compose_args[@]}" config --format json)
printf '%s' "$rendered" | jq -e '
  (.services.elasticsearch.ports // [] | length)==0 and
  (.services.logstash.ports // [] | length)==0 and
  (.services.elasticsearch.environment.ELASTIC_PASSWORD_FILE=="/run/flare-secrets/elasticsearch.password") and
  ((.services.elasticsearch.environment|keys|map(test("PASSWORD$") or test("ENCRYPTIONKEY$"))|any)==false) and
  ((.services.logstash.environment|keys|map(test("PASSWORD$") or test("ENCRYPTIONKEY$"))|any)==false) and
  ((.services.kibana.environment|keys|map(test("PASSWORD$") or test("ENCRYPTIONKEY$"))|any)==false) and
  ([.services|to_entries[]|select((.value.networks // {})|has("observability-beats"))|.key]|sort)==["filebeat","logstash"]
' >/dev/null

docker compose "${compose_args[@]}" run --rm --no-deps filebeat \
  filebeat test config --strict.perms=false --path.data /tmp/filebeat-data
validation_settings=$(mktemp -d)
trap 'rm -rf "$validation_settings"' EXIT
# The live service owns the persistent-queue lock. Validate against an
# ephemeral data path while retaining the same settings and secure keystore.
sed '/^path.queue:/d' observability/logstash/config/logstash.yml >"${validation_settings}/logstash.yml"
install -m 0600 .secrets/observability/monitor/logstash.keystore \
  "${validation_settings}/logstash.keystore"
docker compose "${compose_args[@]}" run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "${validation_settings}:/tmp/flare-logstash-settings:ro" logstash \
  logstash -t --path.settings /tmp/flare-logstash-settings \
  --path.data /tmp/flare-logstash-data -f /usr/share/logstash/pipeline

printf 'Observability shell, JSON/NDJSON, Compose, Filebeat and Logstash checks passed.\n'
