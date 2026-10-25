#!/usr/bin/env bash
set -Eeuo pipefail

# Usage: WEB_HOST=ubuntu@<web-eip> AWS_PROVIDER_KEYS_DIR=<aws-bundle>/prevention \
#   ./observability/scripts/deploy-web.sh
# Preconditions: /opt/flare/.env exists on Web with the lab's non-placeholder
# app credentials, NGINX_PUBLIC_SERVER_NAME=<web-eip>, the exact HTTP CORS
# origin, and FILEBEAT_LOGSTASH_HOST=10.20.10.20:5044. The generated Web mTLS
# directory must exist locally but is ignored by Git.
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
: "${WEB_HOST:?Set WEB_HOST, for example ubuntu@203.0.113.10}"
[[ "$WEB_HOST" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$ ]] || exit 2
: "${AWS_WEB_BUNDLE_DIR:?Run fetch-aws-web-bundle.sh and set its AWS-only bundle directory}"
SSH_OPTIONS=${SSH_OPTIONS:-"-o BatchMode=yes -o StrictHostKeyChecking=accept-new"}
read -r -a ssh_options <<<"$SSH_OPTIONS"
AWS_WEB_BUNDLE_DIR=$(realpath -e -- "$AWS_WEB_BUNDLE_DIR")
case "$AWS_WEB_BUNDLE_DIR" in "$ROOT_DIR/.secrets/aws-lab/"*) ;; *) printf 'Use a separate AWS bundle under .secrets/aws-lab.\n' >&2; exit 2;; esac
CERTS_DIR="$AWS_WEB_BUNDLE_DIR/web"
READER_FILE="$AWS_WEB_BUNDLE_DIR/monitor/siem-reader.password"
: "${AWS_PROVIDER_KEYS_DIR:?Set AWS_PROVIDER_KEYS_DIR to the provider-key directory inside this AWS-only bundle}"
PROVIDER_DIR=$(realpath -e -- "$AWS_PROVIDER_KEYS_DIR")
[[ "$PROVIDER_DIR" == "$AWS_WEB_BUNDLE_DIR/prevention" ]] || {
  printf 'Provider keys must come from this AWS-only bundle, never the local prevention secret directory.\n' >&2
  exit 2
}
require_private_secret() {
  local file=$1 owner mode links size
  [ -f "$file" ] && [ -s "$file" ] && [ ! -L "$file" ] || {
    printf 'Missing private AWS service credential file.\n' >&2
    exit 1
  }
  owner=$(stat -c '%u' -- "$file")
  mode=$(stat -c '%a' -- "$file")
  links=$(stat -c '%h' -- "$file")
  size=$(stat -c '%s' -- "$file")
  [ "$owner" = "$(id -u)" ] && [ "$mode" = "600" ] && [ "$links" = "1" ] && [ "$size" -le 256 ] || {
    printf 'AWS service credential must be owner-only, single-link and at most 256 bytes.\n' >&2
    exit 1
  }
}
require_private_secret "$READER_FILE"
require_private_secret "$PROVIDER_DIR/ipinfo.token"
require_private_secret "$PROVIDER_DIR/abuseipdb.key"

[ -r "${CERTS_DIR}/ca.crt" ] && [ -r "${CERTS_DIR}/filebeat-web.crt" ] && [ -r "${CERTS_DIR}/filebeat-web.key" ] || {
  printf 'Missing AWS Filebeat bundle. Run fetch-aws-web-bundle.sh first.\n' >&2
  exit 1
}

staging=$(ssh "${ssh_options[@]}" "$WEB_HOST" 'mktemp -d /tmp/flare-web-XXXXXXXX')
[[ "$staging" =~ ^/tmp/flare-web-[A-Za-z0-9]{8}$ ]] || { printf 'Invalid remote staging path.\n' >&2; exit 1; }
rsync -az --delete \
  --exclude '.git' --exclude '.terraform' --exclude '.secrets' \
  --include '.env*.example' --exclude '.env*' --exclude '*.pem' --exclude '*.key' \
  --exclude '*.tfstate*' --exclude '*.tfvars' --exclude '*.tfvars.json' --exclude '*.tfplan' \
  --exclude 'audit-results' --exclude 'desktop-client/target' --exclude '__pycache__' \
  --exclude 'backend/target' --exclude 'frontend/node_modules' --exclude 'frontend/dist' \
  --exclude 'frontend/coverage' --exclude 'observability/runtime' --exclude 'observability/data' \
  -e "ssh ${SSH_OPTIONS}" "${ROOT_DIR}/" "${WEB_HOST}:${staging}/source/"
rsync -az --delete -e "ssh ${SSH_OPTIONS}" "${CERTS_DIR}/" "${WEB_HOST}:${staging}/web/"
rsync -az -e "ssh ${SSH_OPTIONS}" "$READER_FILE" "$PROVIDER_DIR/ipinfo.token" "$PROVIDER_DIR/abuseipdb.key" "${WEB_HOST}:${staging}/web/"

ssh "${ssh_options[@]}" "$WEB_HOST" 'test -f /opt/flare/.env || { echo "Create /opt/flare/.env from .env.aws.example first" >&2; exit 1; }'
ssh "${ssh_options[@]}" "$WEB_HOST" bash -se -- "$staging" <<'WEB_INSTALL'
  set -eu
  staging=$1
  [[ "$staging" =~ ^/tmp/flare-web-[A-Za-z0-9]{8}$ ]] || exit 2
  certs_parent=/opt/flare/.secrets/observability
  certs_target=${certs_parent}/web
  certs_next=${certs_parent}/web.next
  certs_previous=${certs_parent}/web.previous
  sudo install -d -m 2750 -o 101 -g 1000 /opt/flare/nginx-logs
  sudo install -d -m 0750 -o 1000 -g 1000 /opt/flare/filebeat-data
  sudo install -d -m 0700 -o 1000 -g 1000 "$certs_parent"
  # Keep the release source outside /opt/flare. With --delete, using a source
  # nested below the destination would let rsync delete that source mid-copy.
  sudo rsync -a --chown=ubuntu:ubuntu --delete \
    --exclude .env --exclude .secrets --exclude nginx-logs --exclude filebeat-data \
    --exclude observability/runtime --exclude observability/data \
    "$staging/source/" /opt/flare/
  sudo rm -rf "$staging/source"

  # Validate the complete staged bundle before replacing the active bind-mount
  # source. Moving the old directory aside prevents mv from nesting a new
  # bundle under it and permits rollback if the final rename fails.
  if sudo test -e "$certs_previous" || sudo test -e "${certs_parent}/web.failed"; then
    echo "A previous Filebeat certificate rotation is unresolved; inspect it before redeploying." >&2
    exit 1
  fi
  sudo rm -rf "$certs_next"
  sudo mv "$staging/web" "$certs_next"
  for cert_file in ca.crt filebeat-web.crt filebeat-web.key siem-reader.password ipinfo.token abuseipdb.key; do
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
  sudo chgrp 10001 "$certs_target/siem-reader.password"
  sudo chmod 0640 "$certs_target/siem-reader.password"
  sudo chmod 0600 "$certs_target/ipinfo.token" "$certs_target/abuseipdb.key"
  sudo env PREVENTION_GROUP_ID=1000 /opt/flare/observability/scripts/bootstrap-prevention.sh
  sudo install -m 0640 -o 1000 -g 1000 "$certs_target/ipinfo.token" /opt/flare/.secrets/prevention/ipinfo.token
  sudo install -m 0640 -o 1000 -g 1000 "$certs_target/abuseipdb.key" /opt/flare/.secrets/prevention/abuseipdb.key
  /opt/flare/observability/scripts/bootstrap-ueba.sh
  chmod 0640 /opt/flare/.secrets/ueba/worker.token
  chgrp 1000 /opt/flare/.secrets/ueba/worker.token
  rmdir "$staging"
WEB_INSTALL
ssh "${ssh_options[@]}" "$WEB_HOST" '
  set -eu
  cd /opt/flare
  certs_parent=/opt/flare/.secrets/observability
  certs_target=${certs_parent}/web
  certs_previous=${certs_parent}/web.previous
  certs_failed=${certs_parent}/web.failed
  logrotate_candidate=/etc/logrotate.d/.flare-nginx.next.$$
  rotation_complete=0
  compose() {
    /opt/flare/observability/scripts/aws-compose.sh web "$@"
  }
  rollback_certificate_bundle() {
    status=$?
    trap - EXIT
    sudo rm -f "$logrotate_candidate"
    if [ "$rotation_complete" -ne 1 ] && sudo test -e "$certs_previous"; then
      echo "Deployment failed; restoring the previous Filebeat certificate bundle." >&2
      if sudo mv "$certs_target" "$certs_failed" && sudo mv "$certs_previous" "$certs_target"; then
        if compose --profile observability up -d --force-recreate --no-deps app filebeat >/dev/null 2>&1; then
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

  # Parse a root-owned candidate with the target host package. Keep the active
  # policy unchanged until the complete Web stack and Filebeat output pass.
  sudo install -m 0644 -o root -g root observability/logrotate/nginx-access "$logrotate_candidate"
  sudo logrotate --debug --state /dev/null "$logrotate_candidate" >/dev/null
  if ! COMPOSE_PROJECT_NAME=flare observability/scripts/migrate-redis-volume.sh check; then
    echo "Redis still uses a legacy anonymous volume. Run the gated migration, then rerun this deployment:" >&2
    echo "  cd /opt/flare && COMPOSE_PROJECT_NAME=flare REDIS_VOLUME_MIGRATION_CONFIRM=yes observability/scripts/migrate-redis-volume.sh prepare" >&2
    exit 1
  fi
  compose build app
  compose build nginx
  compose build gateway
  compose build ueba-worker
  compose up --wait --wait-timeout 180 -d ueba-worker
  compose --profile observability up --wait --wait-timeout 300 -d

  # Compose does not recreate a container when only the contents behind its
  # file bind mounts change. Force recreation so Filebeat opens the new cert
  # inodes, then prove that the new bundle can reach the Logstash output.
  compose --profile observability up --wait --wait-timeout 180 -d --force-recreate --no-deps app filebeat
  compose exec -T filebeat filebeat test output --strict.perms=false --path.data /tmp/filebeat-output-test
  /opt/flare/observability/scripts/check-aws-readiness.sh
  if test -f observability/runtime/redis-migration/state.json; then
    COMPOSE_PROJECT_NAME=flare observability/scripts/migrate-redis-volume.sh verify
  fi

  sudo mv "$logrotate_candidate" /etc/logrotate.d/flare-nginx
  sudo rm -rf "$certs_previous"
  rotation_complete=1
  trap - EXIT
'

printf 'Web deployed. Verify: curl -i http://<web-eip>/api/health and docker compose logs filebeat.\n'
