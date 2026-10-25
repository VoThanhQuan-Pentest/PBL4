#!/usr/bin/env bash
set -Eeuo pipefail

# Usage: MONITOR_HOST=ubuntu@<monitor-eip> ./observability/scripts/deploy-monitor.sh
# This script deliberately has no Terraform apply command. Infrastructure
# creation remains a reviewed, explicit Terraform operation.
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
: "${MONITOR_HOST:?Set MONITOR_HOST, for example ubuntu@203.0.113.20}"
[[ "$MONITOR_HOST" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$ ]] || exit 2
SSH_OPTIONS=${SSH_OPTIONS:-"-o BatchMode=yes -o StrictHostKeyChecking=accept-new"}
read -r -a ssh_options <<<"$SSH_OPTIONS"

staging=$(ssh "${ssh_options[@]}" "$MONITOR_HOST" 'mktemp -d /tmp/flare-monitor-XXXXXXXX')
[[ "$staging" =~ ^/tmp/flare-monitor-[A-Za-z0-9]{8}$ ]] || exit 2
rsync -az --delete --exclude '.secrets' --exclude 'runtime' --exclude 'data' \
  -e "ssh ${SSH_OPTIONS}" "${ROOT_DIR}/observability/" "${MONITOR_HOST}:${staging}/"

ssh "${ssh_options[@]}" "$MONITOR_HOST" bash -se -- "$staging" <<'MONITOR_INSTALL'
  set -eu
  staging=$1
  [[ "$staging" =~ ^/tmp/flare-monitor-[A-Za-z0-9]{8}$ ]] || exit 2
  sudo install -d -m 0750 -o ubuntu -g ubuntu /opt/flare
  sudo install -d -m 0750 -o ubuntu -g ubuntu /opt/flare/observability
  sudo rsync -a --delete --exclude runtime --exclude data "$staging/" /opt/flare/observability/
  sudo chown -R ubuntu:ubuntu /opt/flare/observability
  sudo mountpoint -q /srv/elastic || { echo "Elasticsearch EBS volume is not mounted at /srv/elastic" >&2; exit 1; }
  sudo install -d -m 0750 -o 1000 -g 0 /srv/elastic/elasticsearch
  sudo rm -rf "$staging"
MONITOR_INSTALL
ssh "${ssh_options[@]}" "$MONITOR_HOST" 'test -f /opt/flare/.secrets/observability/monitor/elasticsearch.password || /opt/flare/observability/scripts/bootstrap-secrets.sh'
ssh "${ssh_options[@]}" "$MONITOR_HOST" '/opt/flare/observability/scripts/aws-compose.sh monitor up --wait --wait-timeout 180 -d elasticsearch'
ssh "${ssh_options[@]}" "$MONITOR_HOST" 'export OBSERVABILITY_ROOT_DIR=/opt/flare COMPOSE_PROJECT_NAME=flare; export OBSERVABILITY_COMPOSE_FILES=/opt/flare/observability/docker-compose.monitor.yml:/opt/flare/observability/docker-compose.monitor-aws.yml; /opt/flare/observability/scripts/setup-elastic.sh'
ssh "${ssh_options[@]}" "$MONITOR_HOST" '
  set -eu
  cd /opt/flare
  # The observability tree was replaced above. Recreate Logstash so its
  # bind-mounted pipeline/config point at the new inodes, then wait for the
  # pipeline API before reporting the deployment as ready.
  observability/scripts/aws-compose.sh monitor up --wait --wait-timeout 300 -d --force-recreate --no-deps logstash
  observability/scripts/aws-compose.sh monitor up --wait --wait-timeout 180 -d kibana
'
ssh "${ssh_options[@]}" "$MONITOR_HOST" 'cd /opt/flare && observability/scripts/backup-kibana-before-import.sh && observability/scripts/setup-kibana.sh'

printf 'Monitor deployed. Copy only the generated web client certificate directory before deploying Web:\n'
printf '  MONITOR_HOST=%s ./observability/scripts/fetch-aws-web-bundle.sh\n' "$MONITOR_HOST"
