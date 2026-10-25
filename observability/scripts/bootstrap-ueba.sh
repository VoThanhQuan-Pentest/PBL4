#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
install -d -m 0750 "${ROOT_DIR}/observability/runtime/ueba-catalog"
secret_dir="${ROOT_DIR}/.secrets/ueba"
token_file="${secret_dir}/worker.token"
install -d -m 0750 "$secret_dir"
if [ ! -e "$token_file" ]; then
  umask 007
  openssl rand -hex 32 >"$token_file"
  chmod 0640 "$token_file"
fi
[ -f "$token_file" ] && [ -s "$token_file" ] || {
  printf 'UEBA service token is missing or empty.\n' >&2
  exit 1
}
printf 'UEBA service token is ready outside Git.\n'
