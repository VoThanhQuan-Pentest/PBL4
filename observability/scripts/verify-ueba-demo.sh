#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
phase=${1:-}
dataset=${UEBA_DEMO_DATASET_ID:-"ueba-$(date -u +%Y%m%d)"}
[[ "$phase" = normal || "$phase" = abnormal ]] || {
  printf 'Usage: %s {normal|abnormal}\n' "$0" >&2; exit 2;
}
[[ "$dataset" =~ ^[a-z0-9][a-z0-9_-]{3,23}$ ]] || {
  printf 'Invalid UEBA_DEMO_DATASET_ID.\n' >&2; exit 2;
}
project=${COMPOSE_PROJECT_NAME:-flare-local-elk}
[ "$project" = flare-local-elk ] || {
  printf 'UEBA demo verification is restricted to the local lab project.\n' >&2; exit 2;
}
export OBSERVABILITY_ROOT_DIR="$ROOT_DIR"
export FILEBEAT_CERTS_DIR="${ROOT_DIR}/.secrets/observability/web"
compose_args=(--env-file "${ROOT_DIR}/.env.e2e.example" --project-name "$project" --profile observability
  -f "${ROOT_DIR}/docker-compose.yml" -f "${ROOT_DIR}/docker-compose.e2e.yml"
  -f "${ROOT_DIR}/observability/docker-compose.monitor.yml"
  -f "${ROOT_DIR}/observability/docker-compose.local.yml")
compose() { docker compose "${compose_args[@]}" "$@"; }
sql_count() {
  # The single-quoted program expands inside the DB container, not here.
  # shellcheck disable=SC2016
  printf '%s\n' "$1" | compose exec -T db sh -ceu \
    'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -N -s -u "$MYSQL_USER" "$MYSQL_DATABASE"'
}
elastic_count() {
  local label=$1
  # The single-quoted program expands inside the Elasticsearch container.
  # shellcheck disable=SC2016
  jq -nc --arg label "$label" --arg prefix "ueba-demo-${dataset}-" \
    '{query:{bool:{must:[{term:{"flare.demo_label":$label}},{term:{"flare.synthetic":true}}],should:[{prefix:{"user.id":$prefix}},{prefix:{"target.user.id":$prefix}}],minimum_should_match:1}}}' |
    compose exec -T elasticsearch bash -ceu '
      password=$(cat /run/flare-secrets/elasticsearch.password)
      curl --fail --silent --show-error --cacert /usr/share/elasticsearch/config/certs/ca.crt \
        --user "elastic:${password}" -H "Content-Type: application/json" \
        --data-binary @- https://localhost:9200/logs-flare.security-lab/_count
    ' | jq -r '.count'
}
expect_at_least() {
  local name=$1 actual=$2 minimum=$3
  [[ "$actual" =~ ^[0-9]+$ ]] && [ "$actual" -ge "$minimum" ] || {
    printf 'FAIL %s: found %s, expected at least %s. Wait for background queues and retry.\n' \
      "$name" "$actual" "$minimum" >&2
    exit 1
  }
  printf 'PASS %s: %s\n' "$name" "$actual"
}
expect_exact() {
  local name=$1 actual=$2 expected=$3
  [ "$actual" = "$expected" ] || {
    printf 'FAIL %s: found %s, expected exactly %s. Wait for ELK queues and retry.\n' \
      "$name" "$actual" "$expected" >&2
    exit 1
  }
  printf 'PASS %s: %s\n' "$name" "$actual"
}

ids="'ueba-demo-${dataset}-1','ueba-demo-${dataset}-2','ueba-demo-${dataset}-3','ueba-demo-${dataset}-4'"
if [ "$phase" = normal ]; then
  customers=$(sql_count "SELECT COUNT(*) FROM tbl_khach_hang WHERE user_id IN (${ids});")
  expect_at_least linked_demo_customers "$customers" 4
  event_count=$(sql_count "SELECT COUNT(*) FROM siem_security_events WHERE demo_label='NORMAL' AND (actor_user_id IN (${ids}) OR target_user_id IN (${ids}));")
  expect_at_least normal_events "$event_count" 2532
  aggregated=$(sql_count "SELECT COUNT(*) FROM siem_security_events WHERE demo_label='NORMAL' AND aggregated_at IS NOT NULL AND (actor_user_id IN (${ids}) OR target_user_id IN (${ids}));")
  expect_at_least aggregated_events "$aggregated" 2532
  exported=$(sql_count "SELECT COUNT(*) FROM siem_security_events WHERE demo_label='NORMAL' AND exported_at IS NOT NULL AND (actor_user_id IN (${ids}) OR target_user_id IN (${ids}));")
  expect_at_least exported_events "$exported" 2532
  windows=$(sql_count "SELECT COUNT(*) FROM siem_account_behavior_windows WHERE demo_label='NORMAL' AND account_id IN (${ids});")
  expect_at_least normal_windows "$windows" 960
  eligible=$(sql_count "SELECT COUNT(*) FROM siem_account_behavior_windows WHERE demo_label='NORMAL' AND account_id IN (${ids}) AND baseline_established=1 AND http_4xx_count<=1 AND http_5xx_count=0 AND failed_login_count<=1 AND sensitive_action_count=0 AND new_ip_flag=0 AND new_user_agent_flag=0 AND unusual_hour_flag=0 AND request_count<60 AND (risk_score IS NULL OR risk_score<30);")
  expect_at_least training_eligible_windows "$eligible" 600
  elastic=$(elastic_count NORMAL)
  expect_exact elastic_security_events "$elastic" "$event_count"
else
  target="ueba-demo-${dataset}-1"
  abnormal=$(sql_count "SELECT COUNT(*) FROM siem_security_events WHERE demo_label='ABNORMAL' AND (actor_user_id='${target}' OR target_user_id='${target}');")
  expect_at_least abnormal_events "$abnormal" 136
  scored=$(sql_count "SELECT COUNT(*) FROM siem_account_behavior_windows WHERE account_id='${target}' AND demo_label='ABNORMAL' AND score_status='SCORED_MODEL' AND model_version IS NOT NULL AND risk_score>=60;")
  expect_at_least model_scored_abnormal_window "$scored" 1
  incidents=$(sql_count "SELECT COUNT(*) FROM siem_incidents i JOIN siem_incident_history h ON h.incident_id=i.id WHERE i.target_user_id='${target}' AND i.origin='UEBA' AND h.action='UEBA_DETECTED';")
  expect_at_least ueba_incident_created_for_l1 "$incidents" 1
  elastic=$(elastic_count ABNORMAL)
  expect_exact elastic_security_events "$elastic" "$abnormal"
fi
printf 'UEBA %s demo checks passed for local dataset %s.\n' "$phase" "$dataset"
