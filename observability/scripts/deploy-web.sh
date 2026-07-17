#!/usr/bin/env bash
set -Eeuo pipefail

# Usage: WEB_HOST=ubuntu@<web-eip> ./observability/scripts/deploy-web.sh
# Preconditions: /opt/flare/.env exists on Web with the lab's non-placeholder
# app credentials, NGINX_PUBLIC_SERVER_NAME=<web-eip>, the exact HTTP CORS
# origin, and FILEBEAT_LOGSTASH_HOST=10.20.10.20:5044. The generated Web mTLS
# directory must exist locally but is ignored by Git.
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
: "${WEB_HOST:?Set WEB_HOST, for example ubuntu@203.0.113.10}"
SSH_OPTIONS=${SSH_OPTIONS:-"-o BatchMode=yes -o StrictHostKeyChecking=accept-new"}
CERTS_DIR="${ROOT_DIR}/.secrets/observability/web"

[ -r "${CERTS_DIR}/ca.crt" ] && [ -r "${CERTS_DIR}/filebeat-web.crt" ] && [ -r "${CERTS_DIR}/filebeat-web.key" ] || {
  printf 'Missing Web Filebeat mTLS files. Deploy Monitor, then copy only .secrets/observability/web/.\n' >&2
  exit 1
}

rsync -az --delete \
  --exclude '.git' --exclude '.terraform' --exclude '.secrets' --exclude '.env' \
  --exclude 'backend/target' --exclude 'frontend/node_modules' --exclude 'frontend/dist' \
  --exclude 'frontend/coverage' --exclude 'observability/runtime' --exclude 'observability/data' \
  -e "ssh ${SSH_OPTIONS}" "${ROOT_DIR}/" "${WEB_HOST}:/tmp/flare-release/"
rsync -az -e "ssh ${SSH_OPTIONS}" "${CERTS_DIR}/" "${WEB_HOST}:/tmp/flare-web-certs/"

ssh ${SSH_OPTIONS} "$WEB_HOST" 'test -f /opt/flare/.env || { echo "Create /opt/flare/.env from .env.aws.example first" >&2; exit 1; }'
ssh ${SSH_OPTIONS} "$WEB_HOST" 'sudo install -d -m 0750 -o ubuntu -g ubuntu /opt/flare/nginx-logs /opt/flare/filebeat-data /opt/flare/.secrets/observability && sudo rm -rf /opt/flare/release && sudo mv /tmp/flare-release /opt/flare/release && sudo rsync -a --delete --exclude .env --exclude .secrets /opt/flare/release/ /opt/flare/ && sudo rm -rf /opt/flare/release && sudo mv /tmp/flare-web-certs /opt/flare/.secrets/observability/web && sudo chown -R ubuntu:ubuntu /opt/flare /opt/flare/nginx-logs /opt/flare/filebeat-data && sudo chmod 0700 /opt/flare/.secrets /opt/flare/.secrets/observability /opt/flare/.secrets/observability/web && sudo chmod 0600 /opt/flare/.secrets/observability/web/*.key'
ssh ${SSH_OPTIONS} "$WEB_HOST" 'sudo cp /opt/flare/observability/logrotate/nginx-access /etc/logrotate.d/flare-nginx && cd /opt/flare && docker compose -f docker-compose.yml -f observability/docker-compose.web-aws.yml build app && docker compose -f docker-compose.yml -f observability/docker-compose.web-aws.yml build nginx && docker compose -f docker-compose.yml -f observability/docker-compose.web-aws.yml --profile observability up -d'

printf 'Web deployed. Verify: curl -i http://<web-eip>/api/health and docker compose logs filebeat.\n'
