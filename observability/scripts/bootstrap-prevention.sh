#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
secret_dir="${ROOT_DIR}/.secrets/prevention"
group_id=${PREVENTION_GROUP_ID:-$(id -g)}
[[ "$group_id" =~ ^[0-9]+$ ]] || { printf 'PREVENTION_GROUP_ID must be numeric.\n' >&2; exit 1; }
install -d -m 0750 -g "$group_id" "$secret_dir"
token_file="${secret_dir}/gateway.token"
if [ ! -e "$token_file" ]; then
  umask 007
  openssl rand -hex 32 >"$token_file"
  chmod 0640 "$token_file"
fi
for file in ipinfo.token abuseipdb.key; do
  if [ ! -e "${secret_dir}/${file}" ]; then
    install -m 0640 /dev/null "${secret_dir}/${file}"
  fi
done
[ -s "$token_file" ] || { printf 'Prevention service token is missing.\n' >&2; exit 1; }
for file in "$token_file" "${secret_dir}/ipinfo.token" "${secret_dir}/abuseipdb.key"; do
  [ -f "$file" ] && [ ! -L "$file" ] || {
    printf 'Prevention secret path must be a regular file.\n' >&2; exit 1;
  }
  chmod 0640 "$file"
  chgrp "$group_id" "$file"
done
printf 'Prevention secrets are ready outside Git; IP provider keys may remain empty.\n'
