#!/bin/sh
set -eu

# Validate the resolved Compose variants rather than only grepping source. This
# prevents a later override from quietly restoring MySQL entrypoint scripts or
# exposing the application container directly.
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"
command -v jq >/dev/null 2>&1 || { printf '%s\n' 'jq is required for resolved Compose ownership checks.' >&2; exit 1; }

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

assert_contains() {
  file=$1
  expected=$2
  message=$3
  grep -F -- "$expected" "$file" >/dev/null || fail "$message"
}

assert_not_contains() {
  file=$1
  rejected=$2
  message=$3
  if grep -F -- "$rejected" "$file" >/dev/null; then
    fail "$message"
  fi
}

service_block() {
  service_name=$1
  awk -v service_name="$service_name" '
    $0 == "  " service_name ":" { inside = 1; next }
    inside && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
    inside { print }
  '
}

assert_safe_resolved_compose() {
  variant_name=$1
  rendered_config=$2

  case "$rendered_config" in
    *docker-entrypoint-initdb.d*|*db-init*)
      fail "$variant_name Compose config mounts a legacy MySQL init script; Flyway must be the only schema source."
      ;;
  esac

  if printf '%s\n' "$rendered_config" | service_block app | grep -q '^[[:space:]]*ports:'; then
    fail "$variant_name Compose config exposes the application container directly; only Nginx may publish HTTP."
  fi

  db_block=$(printf '%s\n' "$rendered_config" | service_block db)
  if printf '%s\n' "$db_block" | grep -q '^[[:space:]]*ports:' \
      && ! printf '%s\n' "$db_block" | grep -q 'host_ip: 127\.0\.0\.1'; then
    fail "$variant_name Compose config publishes MySQL outside loopback."
  fi
}

assert_digest_pins() {
  if awk '
    $1 == "image:" && $2 !~ /@sha256:/ {
      print FILENAME ":" FNR ": image is not digest pinned: " $0
      invalid = 1
    }
    END { exit invalid }
  ' docker-compose.yml docker-compose.dev.yml docker-compose.e2e.yml observability/docker-compose.monitor.yml; then
    :
  else
    fail "All Compose runtime images must use immutable SHA-256 digests."
  fi

  if awk '
    $1 == "FROM" && $2 !~ /@sha256:/ {
      print FILENAME ":" FNR ": base image is not digest pinned: " $0
      invalid = 1
    }
    END { exit invalid }
  ' backend/Dockerfile nginx/Dockerfile observability/tests/logrotate/Dockerfile; then
    :
  else
    fail "All Dockerfile base images must use immutable SHA-256 digests."
  fi
}

assert_aws_bind_mount_permissions() {
  assert_contains nginx/Dockerfile 'USER 101:101' \
    'Nginx runtime UID/GID must stay explicit for host bind-mount ownership.'
  assert_contains docker-compose.yml 'chown -R 101:1000 /var/log/nginx' \
    'Compose must migrate existing Nginx log volumes to the shared Nginx/Filebeat ownership contract.'
  assert_contains docker-compose.yml 'user: "0:1000"' \
    'The Nginx log initializer must traverse an already-secured GID-1000 directory without DAC_OVERRIDE.'
  assert_contains docker-compose.yml 'chmod 2750 /var/log/nginx' \
    'Compose must keep the Nginx log directory traversable only by Nginx and Filebeat.'
  assert_contains docker-compose.yml 'nginx-logs-init:' \
    'Nginx and Filebeat must wait for the Nginx log-volume ownership initializer.'
  assert_contains docker-compose.yml 'redis-data:/data' \
    'Redis must use an explicit project-scoped volume rather than an anonymous image volume.'
  assert_contains docker-compose.yml 'user: "1000:1000"' \
    'Filebeat UID/GID must stay explicit for shared Nginx-log access.'
  assert_contains observability/docker-compose.monitor.yml 'user: "1000:0"' \
    'Elasticsearch UID/GID must stay explicit for host data ownership.'
  assert_contains observability/docker-compose.monitor.yml '/_node/pipelines/main?pretty=false' \
    'Logstash must expose a pipeline-aware container healthcheck.'
  assert_contains terraform/templates/web-cloud-init.yaml.tftpl \
    'install -d -m 2750 -o 101 -g 1000 /opt/flare/nginx-logs' \
    'Web cloud-init must create the Nginx log directory for nginx UID 101 and Filebeat GID 1000.'
  assert_contains terraform/templates/web-cloud-init.yaml.tftpl \
    'install -m 0640 -o 101 -g 1000 /dev/null /opt/flare/nginx-logs/access.json.log' \
    'Web cloud-init must pre-create the access log with shared read ownership.'
  assert_contains observability/docker-compose.web-aws.yml \
    'nginx-logs-init:' \
    'The AWS override must initialize the same host bind mount consumed by Nginx and Filebeat.'
  assert_contains observability/logrotate/nginx-access 'create 0640 root root' \
    'Logrotate parsing must not depend on container-only identities existing in the host NSS database.'
  logrotate_policy=$(cat observability/logrotate/nginx-access)
  case "$logrotate_policy" in
    *'create 0640 root root'*'/usr/bin/chown 101:1000 /opt/flare/nginx-logs/*.log'*'/usr/bin/chmod 0640 /opt/flare/nginx-logs/*.log'*'kill -s USR1 nginx'*) ;;
    *) fail 'Logrotate must set numeric ownership and mode before signaling Nginx.' ;;
  esac
  assert_contains observability/logrotate/nginx-access 'maxsize 10M' \
    'Logrotate must retain daily rotation while enforcing the 10 MB upper bound.'
  assert_not_contains observability/logrotate/nginx-access '    size 10M' \
    'Logrotate size must not override the daily schedule; use maxsize.'
  assert_not_contains observability/logrotate/nginx-access "flare-nginx-logrotate 'Failed to signal running nginx after log rotation'; true" \
    'Logrotate must fail visibly when a running Nginx cannot reopen its log files.'

  web_deploy=$(cat observability/scripts/deploy-web.sh)
  # These literal shell fragments are assertions about the deploy script.
  # shellcheck disable=SC2016
  case "$web_deploy" in
    *'--exclude nginx-logs --exclude filebeat-data'*'sudo chown -R 101:1000 /opt/flare/nginx-logs'*'sudo chmod 2750 /opt/flare/nginx-logs'*) ;;
    *) fail 'Web deploy must preserve runtime bind mounts and restore Nginx/Filebeat log ownership after release sync.' ;;
  esac
  case "$web_deploy" in
    *'migrate-redis-volume.sh check'*'migrate-redis-volume.sh prepare'*'migrate-redis-volume.sh verify'*) ;;
    *) fail 'Web deployment must fail closed until legacy Redis data has been migrated and verified.' ;;
  esac
  # shellcheck disable=SC2016
  case "$web_deploy" in
    *'sudo mv /tmp/flare-web-certs "$certs_next"'*'sudo openssl verify -CAfile "$certs_next/ca.crt"'*'sudo mv "$certs_target" "$certs_previous"'*'sudo mv "$certs_next" "$certs_target"'*'--force-recreate --no-deps filebeat'*'filebeat test output'*) ;;
    *) fail 'Web deploy must validate and replace the exact Filebeat certificate bundle, recreate Filebeat and test its output.' ;;
  esac

  monitor_cloud_init=$(cat terraform/templates/monitor-cloud-init.yaml.tftpl)
  # Terraform template interpolation must remain literal in this assertion.
  # shellcheck disable=SC2016
  case "$monitor_cloud_init" in
    *'grep -Fq "UUID=$${uuid} /srv/elastic " /etc/fstab'*'mountpoint -q /srv/elastic || mount /srv/elastic'*'install -d -m 0750 -o 1000 -g 0 /srv/elastic/elasticsearch'*) ;;
    *) fail 'Monitor cloud-init must create the Elasticsearch bind source as 1000:0 after mounting EBS.' ;;
  esac

  monitor_deploy=$(cat observability/scripts/deploy-monitor.sh)
  case "$monitor_deploy" in
    *'sudo mountpoint -q /srv/elastic'*'sudo install -d -m 0750 -o 1000 -g 0 /srv/elastic/elasticsearch'*) ;;
    *) fail 'Monitor deploy must verify EBS and create the Elasticsearch bind source as 1000:0.' ;;
  esac
  case "$monitor_deploy" in
    *'up --wait --wait-timeout 300 -d --force-recreate --no-deps logstash'*) ;;
    *) fail 'Monitor deploy must recreate Logstash and wait for its pipeline health after replacing bind mounts.' ;;
  esac
  assert_not_contains observability/scripts/deploy-monitor.sh \
    'chown -R ubuntu:ubuntu /opt/flare/observability /srv/elastic' \
    'Monitor deploy must not recursively give Elasticsearch data to the SSH user.'
}

assert_docker_context_hardening() {
  for ignore_file in .dockerignore backend/.dockerignore; do
    assert_contains "$ignore_file" '.secrets/' "$ignore_file must exclude the local secrets tree."
    assert_contains "$ignore_file" '**/*.key' "$ignore_file must exclude private keys."
    assert_contains "$ignore_file" '**/*.crt' "$ignore_file must exclude certificates."
    assert_contains "$ignore_file" '**/.terraform/' "$ignore_file must exclude Terraform working directories."
    assert_contains "$ignore_file" '**/*.tfstate' "$ignore_file must exclude Terraform state."
    assert_contains "$ignore_file" '!**/.env.example' "$ignore_file must retain explicit environment examples."
    assert_contains "$ignore_file" '!**/.env.*.example' "$ignore_file must retain named environment examples."
    assert_contains "$ignore_file" '!**/*.tfvars.example' "$ignore_file must retain explicit Terraform variable examples."
    assert_not_contains "$ignore_file" '!**/*.example' \
      "$ignore_file must not broadly re-include arbitrary example files after secret exclusions."
  done
  assert_contains .dockerignore 'observability/runtime/' 'Docker build contexts must exclude observability runtime output.'
}

assert_aws_bind_mount_permissions
assert_docker_context_hardening

export COMPOSE_PROJECT_NAME=pbl4-hardening-check
base_config=$(docker compose --env-file .env.example config)
dev_config=$(docker compose --env-file .env.example -f docker-compose.yml -f docker-compose.dev.yml config)
e2e_config=$(docker compose --env-file .env.e2e.example -f docker-compose.yml -f docker-compose.e2e.yml config)
aws_web_config=$(docker compose --env-file .env.example -f docker-compose.yml -f observability/docker-compose.web-aws.yml config)
base_json=$(docker compose --env-file .env.example --profile observability config --format json)
aws_web_json=$(docker compose --env-file .env.example --profile observability -f docker-compose.yml -f observability/docker-compose.web-aws.yml config --format json)

assert_safe_resolved_compose base "$base_config"
assert_safe_resolved_compose dev "$dev_config"
assert_safe_resolved_compose e2e "$e2e_config"
assert_safe_resolved_compose aws-web "$aws_web_config"
printf '%s' "$base_json" | jq -e '
  .services["nginx-logs-init"].user=="0:1000" and
  (.services["nginx-logs-init"].cap_add|sort)==["CHOWN","FOWNER"] and
  ([.services.redis.volumes[]|select(.target=="/data")]|length)==1 and
  ([.services.redis.volumes[]|select(.target=="/data")][0].type)=="volume" and
  ([.services.redis.volumes[]|select(.target=="/data")][0].source)=="redis-data"
' >/dev/null || fail 'Resolved base Compose must retain least-privilege log initialization and a declared Redis data volume.'
printf '%s' "$aws_web_json" | jq -e '
  ([.services["nginx-logs-init"].volumes[],.services.nginx.volumes[],.services.filebeat.volumes[]]
    | map(select(.target=="/var/log/nginx"))) as $logs |
  ($logs|length)==3 and all($logs[];.type=="bind" and .source=="/opt/flare/nginx-logs")
' >/dev/null || fail 'Resolved AWS Compose must bind the same host log directory into init, Nginx and Filebeat.'
assert_digest_pins

printf '%s\n' 'Compose, deployment and Docker-context hardening checks passed.'
