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
rsync -az --delete -e "ssh ${SSH_OPTIONS}" "${CERTS_DIR}/" "${WEB_HOST}:/tmp/flare-web-certs/"

ssh ${SSH_OPTIONS} "$WEB_HOST" 'test -f /opt/flare/.env || { echo "Create /opt/flare/.env from .env.aws.example first" >&2; exit 1; }'
ssh ${SSH_OPTIONS} "$WEB_HOST" '
  set -eu
  certs_parent=/opt/flare/.secrets/observability
  certs_target=${certs_parent}/web
  certs_next=${certs_parent}/web.next
  certs_previous=${certs_parent}/web.previous
  sudo install -d -m 2750 -o 101 -g 1000 /opt/flare/nginx-logs
  sudo install -d -m 0750 -o 1000 -g 1000 /opt/flare/filebeat-data
  sudo install -d -m 0700 -o 1000 -g 1000 "$certs_parent"
  sudo rm -rf /opt/flare/release
  sudo mv /tmp/flare-release /opt/flare/release
  sudo rsync -a --chown=ubuntu:ubuntu --delete \
    --exclude .env --exclude .secrets --exclude nginx-logs --exclude filebeat-data \
    --exclude observability/runtime --exclude observability/data \
    /opt/flare/release/ /opt/flare/
  sudo rm -rf /opt/flare/release

  # Validate the complete staged bundle before replacing the active bind-mount
  # source. Moving the old directory aside prevents mv from nesting a new
  # bundle under it and permits rollback if the final rename fails.
  if sudo test -e "$certs_previous" || sudo test -e "${certs_parent}/web.failed"; then
    echo "A previous Filebeat certificate rotation is unresolved; inspect it before redeploying." >&2
    exit 1
  fi
  sudo rm -rf "$certs_next"
  sudo mv /tmp/flare-web-certs "$certs_next"
  for cert_file in ca.crt filebeat-web.crt filebeat-web.key; do
    sudo test -s "$certs_next/$cert_file" || {
      echo "Invalid staged Filebeat certificate bundle: $cert_file is missing or empty" >&2
      exit 1
    }
  done
  sudo openssl x509 -in "$certs_next/ca.crt" -noout -checkend 0
  sudo openssl x509 -in "$certs_next/filebeat-web.crt" -noout -checkend 0
  sudo openssl pkey -in "$certs_next/filebeat-web.key" -noout
  sudo openssl verify -CAfile "$certs_next/ca.crt" "$certs_next/filebeat-web.crt"
  cert_modulus=$(sudo openssl x509 -in "$certs_next/filebeat-web.crt" -noout -modulus)
  key_modulus=$(sudo openssl rsa -in "$certs_next/filebeat-web.key" -noout -modulus 2>/dev/null)
  test "$cert_modulus" = "$key_modulus" || {
    echo "Invalid staged Filebeat certificate bundle: certificate and key do not match" >&2
    exit 1
  }
  sudo chown -R 1000:1000 "$certs_next"
  sudo find "$certs_next" -type d -exec chmod 0700 {} +
  sudo find "$certs_next" -type f -exec chmod 0644 {} +
  sudo chmod 0600 "$certs_next"/*.key
  if sudo test -e "$certs_target"; then
    sudo mv "$certs_target" "$certs_previous"
  fi
  if ! sudo mv "$certs_next" "$certs_target"; then
    sudo test ! -e "$certs_previous" || sudo mv "$certs_previous" "$certs_target"
    exit 1
  fi

  sudo chown -R 1000:1000 /opt/flare/filebeat-data /opt/flare/.secrets
  sudo touch /opt/flare/nginx-logs/access.json.log /opt/flare/nginx-logs/error.log
  sudo chown -R 101:1000 /opt/flare/nginx-logs
  sudo find /opt/flare/nginx-logs -type f -exec chmod 0640 {} +
  sudo chmod 2750 /opt/flare/nginx-logs
  sudo chmod 0700 /opt/flare/.secrets "$certs_parent" "$certs_target"
  sudo chmod 0600 "$certs_target"/*.key
'
ssh ${SSH_OPTIONS} "$WEB_HOST" '
  set -eu
  cd /opt/flare
  certs_parent=/opt/flare/.secrets/observability
  certs_target=${certs_parent}/web
  certs_previous=${certs_parent}/web.previous
  certs_failed=${certs_parent}/web.failed
  rotation_complete=0
  compose() {
    docker compose -f docker-compose.yml -f observability/docker-compose.web-aws.yml "$@"
  }
  rollback_certificate_bundle() {
    status=$?
    trap - EXIT
    if [ "$rotation_complete" -ne 1 ] && sudo test -e "$certs_previous"; then
      echo "Deployment failed; restoring the previous Filebeat certificate bundle." >&2
      if sudo mv "$certs_target" "$certs_failed" && sudo mv "$certs_previous" "$certs_target"; then
        if compose --profile observability up -d --force-recreate --no-deps filebeat >/dev/null 2>&1; then
          sudo rm -rf "$certs_failed"
        else
          echo "Previous certificates were restored, but Filebeat recreation failed; inspect $certs_failed." >&2
        fi
      else
        echo "Automatic certificate rollback failed; inspect $certs_parent before restarting Filebeat." >&2
      fi
    fi
    exit "$status"
  }
  trap rollback_certificate_bundle EXIT

  sudo cp observability/logrotate/nginx-access /etc/logrotate.d/flare-nginx
  compose build app
  compose build nginx
  compose --profile observability up -d

  # Compose does not recreate a container when only the contents behind its
  # file bind mounts change. Force recreation so Filebeat opens the new cert
  # inodes, then prove that the new bundle can reach the Logstash output.
  compose --profile observability up -d --force-recreate --no-deps filebeat
  compose exec -T filebeat filebeat test output --strict.perms=false --path.data /tmp/filebeat-output-test

  sudo rm -rf "$certs_previous"
  rotation_complete=1
  trap - EXIT
'

printf 'Web deployed. Verify: curl -i http://<web-eip>/api/health and docker compose logs filebeat.\n'
