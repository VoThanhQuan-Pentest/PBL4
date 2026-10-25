#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SECRETS_DIR=${OBSERVABILITY_SECRETS_DIR:-"${ROOT_DIR}/.secrets/observability"}
PASSWORD_FILE="${SECRETS_DIR}/monitor/elasticsearch.password"
KIBANA_URL=${KIBANA_URL:-http://127.0.0.1:5601}
RUNTIME_DIR="${ROOT_DIR}/observability/runtime"
OUTPUT=${1:-"${RUNTIME_DIR}/kibana-9.4.2-export.ndjson"}

[[ "$KIBANA_URL" =~ ^http://(127\.0\.0\.1|localhost):([0-9]{1,5})$ ]] || {
  printf 'Kibana export requires an exact loopback HTTP origin.\n' >&2
  exit 2
}
port=${BASH_REMATCH[2]}
(( 10#$port >= 1 && 10#$port <= 65535 )) || {
  printf 'Kibana export port is outside the valid range.\n' >&2
  exit 2
}
[ -f "$PASSWORD_FILE" ] && [ ! -L "$PASSWORD_FILE" ] && [ -r "$PASSWORD_FILE" ] \
  && [ "$(stat -c '%u' "$PASSWORD_FILE")" = "$(id -u)" ] || {
    printf 'Missing or unprotected Elasticsearch password file.\n' >&2
    exit 1
  }
password_mode=$(stat -c '%a' "$PASSWORD_FILE")
password_group=$(stat -c '%g' "$PASSWORD_FILE")
password_parent=$(dirname -- "$PASSWORD_FILE")
[[ -d "$password_parent" && ! -L "$password_parent" \
  && "$(stat -c '%a' "$password_parent")" = 700 \
  && "$(stat -c '%u' "$password_parent")" = "$(id -u)" ]] || {
    printf 'Elasticsearch password parent must be owner-only.\n' >&2
    exit 1
  }
# bootstrap-secrets.sh deliberately sets this bind-mounted Elasticsearch
# runtime password to 0640:root so the pinned container can read it. The
# private 0700 parent prevents host group access. Other secrets must be 0600.
case "${password_mode}:${password_group}" in
  600:*) ;;
  640:0) ;;
  *) printf 'Elasticsearch password file has an unapproved mode/group.\n' >&2; exit 1 ;;
esac
for binary in curl jq realpath stat; do
  command -v "$binary" >/dev/null || { printf 'Missing required command: %s\n' "$binary" >&2; exit 1; }
done
[ -d "$RUNTIME_DIR" ] && [ ! -L "$RUNTIME_DIR" ] || {
  printf 'Kibana export runtime directory must be an existing real directory.\n' >&2
  exit 2
}
runtime_real=$(realpath -e -- "$RUNTIME_DIR")
case "$OUTPUT" in
  /*) requested_output=$OUTPUT ;;
  *) requested_output="${ROOT_DIR}/${OUTPUT}" ;;
esac
[ ! -L "$requested_output" ] || { printf 'Kibana export refuses a symlink output.\n' >&2; exit 2; }
output_parent=$(dirname -- "$requested_output")
[ -d "$output_parent" ] || { printf 'Kibana export parent directory must already exist.\n' >&2; exit 2; }
output_parent=$(realpath -e -- "$output_parent")
case "$output_parent/" in
  "$runtime_real/"*) ;;
  *) printf 'Kibana export output must stay under observability/runtime.\n' >&2; exit 2 ;;
esac
mode=$(stat -c '%a' "$output_parent")
owner=$(stat -c '%u' "$output_parent")
(( (8#$mode & 0022) == 0 )) && [ "$owner" = "$(id -u)" ] || {
  printf 'Kibana export parent must be owner-controlled and not group/world writable.\n' >&2
  exit 2
}
OUTPUT="${output_parent}/$(basename -- "$requested_output")"
[ "$OUTPUT" != "$runtime_real" ] || { printf 'Kibana export output must be a file.\n' >&2; exit 2; }
if [ -e "$OUTPUT" ] || [ -L "$OUTPUT" ]; then
  [ -f "$OUTPUT" ] && [ ! -L "$OUTPUT" ] && [ -O "$OUTPUT" ] \
    && [ "$(stat -c '%h' "$OUTPUT")" = 1 ] || {
      printf 'Kibana export refuses a non-regular, linked or foreign existing output.\n' >&2
      exit 2
    }
fi
umask 077
tmp=$(mktemp "${output_parent}/.kibana-export.XXXXXX")
trap '[[ -z "${tmp:-}" ]] || rm -f -- "$tmp"' EXIT
password=$(<"$PASSWORD_FILE")
curl --fail --silent --show-error --connect-timeout 5 --max-time 120 \
  --config <(printf 'user = "elastic:%s"\n' "$password") \
  -H 'kbn-xsrf: flare-local-elk' -H 'Content-Type: application/json' -X POST \
  --data-binary '{"objects":[{"type":"dashboard","id":"flare-overview"},{"type":"dashboard","id":"flare-geoip"},{"type":"dashboard","id":"flare-security"}],"includeReferencesDeep":true,"excludeExportDetails":false}' \
  "${KIBANA_URL}/s/flare-lab/api/saved_objects/_export" >"$tmp"
jq -s -e 'length > 0 and all(.[]; type == "object")' "$tmp" >/dev/null || {
  printf 'Kibana saved-object export is empty or malformed.\n' >&2
  exit 1
}
chmod 0600 "$tmp"
mv -- "$tmp" "$OUTPUT"
tmp=
printf 'Official Kibana saved-object export written to %s\n' "$OUTPUT"
