#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
: "${MONITOR_HOST:?Set MONITOR_HOST to ubuntu@Monitor-EIP}"
[[ "$MONITOR_HOST" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$ ]] || exit 2
read -r -a ssh_options <<<"${SSH_OPTIONS:--o BatchMode=yes -o StrictHostKeyChecking=accept-new}"
umask 077
install -d -m 0700 "$ROOT_DIR/.secrets/aws-lab"
dest=$(mktemp -d "$ROOT_DIR/.secrets/aws-lab/web-bundle-XXXXXX")
install -d -m 0700 "$dest/prevention"
# Fixed allowlist: no CA key, server key or Elasticsearch administrator secret.
ssh "${ssh_options[@]}" "$MONITOR_HOST" 'set -eu
  cd /opt/flare/.secrets/observability
  openssl x509 -in monitor/elasticsearch.crt -noout -checkip 10.20.10.20 >&2
  tar -czf - web/ca.crt web/filebeat-web.crt web/filebeat-web.key monitor/siem-reader.password
' | tar -xzf - -C "$dest" --no-same-owner
for path in web/ca.crt web/filebeat-web.crt web/filebeat-web.key monitor/siem-reader.password; do
  [ -f "$dest/$path" ] && [ -s "$dest/$path" ] && [ ! -L "$dest/$path" ] || exit 1
  chmod 0600 "$dest/$path"
done
printf 'AWS-only bundle created: %s\nPlace AWS-specific IPinfo/AbuseIPDB keys in its prevention/ directory with mode 0600.\nUse this directory as AWS_WEB_BUNDLE_DIR and its prevention/ child as AWS_PROVIDER_KEYS_DIR.\n' "$dest"
