#!/usr/bin/env bash
set -Eeuo pipefail

# Usage: MONITOR_HOST=ubuntu@<monitor-eip> ./observability/scripts/deploy-monitor.sh
# This script deliberately has no Terraform apply command. Infrastructure
# creation remains a reviewed, explicit Terraform operation.
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
: "${MONITOR_HOST:?Set MONITOR_HOST, for example ubuntu@203.0.113.20}"
SSH_OPTIONS=${SSH_OPTIONS:-"-o BatchMode=yes -o StrictHostKeyChecking=accept-new"}

rsync -az --delete --exclude '.secrets' --exclude 'runtime' \
  -e "ssh ${SSH_OPTIONS}" "${ROOT_DIR}/observability/" "${MONITOR_HOST}:/tmp/flare-observability/"

ssh ${SSH_OPTIONS} "$MONITOR_HOST" 'sudo install -d -m 0750 -o ubuntu -g ubuntu /opt/flare && sudo rm -rf /opt/flare/observability && sudo mv /tmp/flare-observability /opt/flare/observability && sudo chown -R ubuntu:ubuntu /opt/flare/observability /srv/elastic'
ssh ${SSH_OPTIONS} "$MONITOR_HOST" 'test -f /opt/flare/.secrets/observability/monitor/elasticsearch.password || /opt/flare/observability/scripts/bootstrap-secrets.sh'
ssh ${SSH_OPTIONS} "$MONITOR_HOST" 'cd /opt/flare && docker compose -f observability/docker-compose.monitor.yml up -d elasticsearch'
ssh ${SSH_OPTIONS} "$MONITOR_HOST" 'cd /opt/flare && /opt/flare/observability/scripts/setup-elastic.sh'
ssh ${SSH_OPTIONS} "$MONITOR_HOST" 'cd /opt/flare && docker compose -f observability/docker-compose.monitor.yml up -d logstash kibana'
ssh ${SSH_OPTIONS} "$MONITOR_HOST" 'cd /opt/flare && /opt/flare/observability/scripts/setup-kibana.sh'

printf 'Monitor deployed. Copy only the generated web client certificate directory before deploying Web:\n'
printf '  rsync -az -e "ssh %s" %s:/opt/flare/.secrets/observability/web/ %s/.secrets/observability/web/\n' "$SSH_OPTIONS" "$MONITOR_HOST" "$ROOT_DIR"
