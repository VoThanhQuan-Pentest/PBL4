#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
umask 077
[ "$ROOT_DIR" = /opt/flare ] || { printf 'Run this on Web EC2 via SSH.\n' >&2; exit 2; }
dest="$ROOT_DIR/observability/runtime/private-credentials/aws-bootstrap.json"
install -d -m 0700 "$(dirname "$dest")"
exec 9>"$(dirname "$dest")/.aws-bootstrap.lock"
flock -n 9 || { printf 'Another bootstrap is running; wait for it to finish.\n' >&2; exit 1; }
[ ! -e "$dest" ] || { printf 'Bootstrap credential already exists; do not overwrite it.\n' >&2; exit 1; }
# Retain failed captures privately: the DB operation may have completed even if SSH/Docker failed.
capture=$(mktemp "$(dirname "$dest")/aws-bootstrap.capture-XXXXXXXX.json")
if ! "$ROOT_DIR/observability/scripts/aws-compose.sh" web exec -T app \
  java -Dloader.main=com.flarefitness.backend.ops.AwsLabBootstrap -cp /app/app.jar \
  org.springframework.boot.loader.launch.PropertiesLauncher >"$capture"; then
  printf 'Bootstrap failed. Private capture retained at %s; inspect locally before retrying.\n' "$capture" >&2
  exit 1
fi
if ! jq -e 'type == "object" and (.id | type == "string" and startswith("aws-bootstrap-"))
    and (.username | type == "string" and startswith("aws_bootstrap_"))
    and (.password | type == "string" and length >= 12)' "$capture" >/dev/null 2>&1; then
  printf 'Bootstrap output invalid. Private capture retained at %s; do not reset an existing Admin.\n' "$capture" >&2
  exit 1
fi
# Hard-link publication is atomic and cannot overwrite an existing credential.
ln -- "$capture" "$dest"
rm -- "$capture"
printf 'Bootstrap credential saved privately: %s\n' "$dest"
