#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
role=${1:-}; shift || true
[[ "$role" = web || "$role" = monitor ]] || { printf 'Usage: %s {web|monitor} <compose arguments>\n' "$0" >&2; exit 2; }
[ "$ROOT_DIR" = /opt/flare ] || { printf 'AWS operator commands require the deployment root /opt/flare.\n' >&2; exit 2; }
export OBSERVABILITY_ROOT_DIR="$ROOT_DIR"
export FILEBEAT_CERTS_DIR="$ROOT_DIR/.secrets/observability/web"
export COMPOSE_PROJECT_NAME=flare
cd "$ROOT_DIR"
if [ "$role" = web ]; then
  if [ ! -f .env ] || ! grep -qx 'FLARE_ENVIRONMENT=aws-lab' .env; then
    printf 'Missing aws-lab environment marker.\n' >&2; exit 2
  fi
  if grep -Eq 'replace-with-|REPLACE_WITH_|^SPRING_PROFILES_ACTIVE=.*(dev|e2e)' .env; then
    printf 'AWS environment contains placeholders or a development profile.\n' >&2; exit 2
  fi
  if [[ "${1:-}" = up || "${1:-}" = run || "${1:-}" = restart ]]; then
    for path in observability/web/siem-reader.password ueba/worker.token prevention/gateway.token observability/web/ca.crt observability/web/filebeat-web.crt observability/web/filebeat-web.key; do
      [ -f ".secrets/$path" ] && [ -s ".secrets/$path" ] || { printf 'Missing regular secret file: %s\n' "$path" >&2; exit 1; }
    done
    for path in prevention/ipinfo.token prevention/abuseipdb.key; do
      [ -f ".secrets/$path" ] || { printf 'Missing provider key file: %s\n' "$path" >&2; exit 1; }
    done
  fi
  exec docker compose --env-file .env -f docker-compose.yml -f observability/docker-compose.web-aws.yml "$@"
fi
export OBSERVABILITY_COMPOSE_FILES="$ROOT_DIR/observability/docker-compose.monitor.yml:$ROOT_DIR/observability/docker-compose.monitor-aws.yml"
if [[ "${1:-}" = up || "${1:-}" = run || "${1:-}" = restart ]]; then
  mountpoint -q /srv/elastic || { printf 'EBS is not mounted at /srv/elastic.\n' >&2; exit 1; }
  for path in ca.crt elasticsearch.crt elasticsearch.key elasticsearch.password logstash.crt logstash.key logstash.keystore kibana.keystore; do
    [ -s ".secrets/observability/monitor/$path" ] && [ -f ".secrets/observability/monitor/$path" ] || { printf 'Missing Monitor secret: %s\n' "$path" >&2; exit 1; }
  done
fi
exec docker compose -f observability/docker-compose.monitor.yml -f observability/docker-compose.monitor-aws.yml "$@"
