#!/usr/bin/env bash
set -Eeuo pipefail

# Produce real 5xx responses through the AWS Web Nginx without adding a test
# endpoint to the application. The app container is always restored by the EXIT
# trap. Run only against the group-owned lab after explicit confirmation.
: "${WEB_HOST:?Set WEB_HOST, for example ubuntu@203.0.113.10}"
: "${FLARE_LAB_TARGET:?Set FLARE_LAB_TARGET to the group-owned Web HTTP origin}"
: "${FLARE_LAB_ALLOWED_HOST:?Set FLARE_LAB_ALLOWED_HOST to the Web EIP host}"
[ "${I_OWN_THIS_TARGET:-}" = "yes" ] || {
  printf 'Set I_OWN_THIS_TARGET=yes after confirming ownership.\n' >&2
  exit 1
}

[[ "$WEB_HOST" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$ ]] || {
  printf 'WEB_HOST must be an explicit user@IPv4-or-hostname SSH target.\n' >&2
  exit 1
}
TARGET=${FLARE_LAB_TARGET%/}
[[ "$TARGET" =~ ^https?://([A-Za-z0-9.-]+)(:[0-9]{1,5})?$ ]] || {
  printf 'FLARE_LAB_TARGET must be one HTTP(S) origin without a path, query or userinfo.\n' >&2
  exit 1
}
target_host=${BASH_REMATCH[1]}
[ "$target_host" = "$FLARE_LAB_ALLOWED_HOST" ] || {
  printf 'Target host is not the explicit allowlist host.\n' >&2
  exit 1
}

SSH_OPTIONS=${SSH_OPTIONS:-"-o BatchMode=yes -o StrictHostKeyChecking=accept-new"}
read -r -a ssh_options <<<"$SSH_OPTIONS"
app_stopped=0

restore_app() {
  local status=$?
  trap - EXIT
  if [ "$app_stopped" -eq 1 ]; then
    printf 'Restoring the Web app container...\n' >&2
    if ! ssh "${ssh_options[@]}" "$WEB_HOST" \
      'cd /opt/flare && docker compose -f docker-compose.yml -f observability/docker-compose.web-aws.yml --profile observability up --wait --wait-timeout 180 -d app'; then
      printf 'Automatic app recovery failed; restore app on Web EC2 immediately.\n' >&2
      status=1
    fi
  fi
  exit "$status"
}
trap restore_app EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ssh "${ssh_options[@]}" "$WEB_HOST" \
  'cd /opt/flare && docker compose -f docker-compose.yml -f observability/docker-compose.web-aws.yml --profile observability config --services | grep -Fx app >/dev/null'
ssh "${ssh_options[@]}" "$WEB_HOST" \
  'cd /opt/flare && docker compose -f docker-compose.yml -f observability/docker-compose.web-aws.yml --profile observability stop -t 30 app'
app_stopped=1

for count in $(seq 1 6); do
  status_code=$(curl --silent --show-error --max-time 10 --output /dev/null \
    --write-out '%{http_code}' "${TARGET}/api/health?aws_5xx_probe=${count}")
  case "$status_code" in
    5??) ;;
    *)
      printf 'Expected a 5xx response for probe %s, received HTTP %s.\n' "$count" "$status_code" >&2
      exit 1
      ;;
  esac
done

ssh "${ssh_options[@]}" "$WEB_HOST" \
  'cd /opt/flare && docker compose -f docker-compose.yml -f observability/docker-compose.web-aws.yml --profile observability up --wait --wait-timeout 180 -d app'
app_stopped=0
printf 'Six real 5xx events were generated and the Web app recovered successfully.\n'
