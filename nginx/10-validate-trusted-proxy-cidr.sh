#!/bin/sh
set -eu

# This runs before the stock 20-envsubst-on-templates.sh entrypoint hook. It
# prevents an operator typo (or a comma-separated list) from turning the
# template substitution below into trust for every direct client.
trusted_proxy_cidr=${NGINX_TRUSTED_PROXY_CIDR:-}

if ! printf '%s\n' "$trusted_proxy_cidr" | awk -F/ '
  BEGIN { valid = 0 }
  NR != 1 { valid = 0; next }
  NF != 2 || $1 == "" || $2 !~ /^[0-9]+$/ || $2 < 0 || $2 > 32 { valid = 0; next }
  $1 == "0.0.0.0" && $2 == "0" { valid = 0; next }
  {
    count = split($1, octets, ".")
    if (count != 4) { valid = 0; next }
    for (octet_index = 1; octet_index <= 4; octet_index++) {
      if (octets[octet_index] !~ /^[0-9]+$/ || octets[octet_index] < 0 || octets[octet_index] > 255) {
        valid = 0
        next
      }
    }
    valid = 1
  }
  END { exit(valid ? 0 : 1) }
'; then
  printf '%s\n' 'NGINX_TRUSTED_PROXY_CIDR must be one specific IPv4 CIDR and must not be 0.0.0.0/0.' >&2
  exit 1
fi

# The value is substituted directly into `server_name`; limit it to one IPv4
# address or DNS host label so an environment typo cannot inject Nginx syntax.
public_server_name=${NGINX_PUBLIC_SERVER_NAME:-}
if ! printf '%s\n' "$public_server_name" | awk '
  NR != 1 || $0 == "" { exit 1 }
  /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/ {
    count = split($0, octets, ".")
    for (octet_index = 1; octet_index <= count; octet_index++) {
      if (octets[octet_index] > 255) exit 1
    }
    exit 0
  }
  /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/ { exit 0 }
  { exit 1 }
'; then
  printf '%s\n' 'NGINX_PUBLIC_SERVER_NAME must be one IPv4 address or DNS hostname.' >&2
  exit 1
fi
