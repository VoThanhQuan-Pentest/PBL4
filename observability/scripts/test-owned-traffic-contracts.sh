#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
stub_dir="${test_dir}/bin"
install -d -m 0700 "$stub_dir"
export FLARE_TRAFFIC_TEST_LOG="${test_dir}/calls.log"

cat >"${stub_dir}/curl" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
joined=$(printf ' %q' "$@")
body=''
emit_status=false
dump_header=''
expect_dump_path=false
for argument in "$@"; do
  if [ "$expect_dump_path" = true ]; then
    dump_header=$argument
    expect_dump_path=false
  fi
  if [ "$argument" = '@-' ]; then
    body=$(cat)
  fi
  if [ "$argument" = '%{http_code}' ]; then
    emit_status=true
  fi
  if [ "$argument" = '--dump-header' ]; then
    expect_dump_path=true
  fi
done
printf 'curl%s body=%s\n' "$joined" "$body" >>"$FLARE_TRAFFIC_TEST_LOG"
case "$joined" in
  *'/api/auth/csrf'*) printf '{"token":"test-csrf-token"}' ;;
esac
if [ "$emit_status" = true ]; then
  printf '%s' "${FLARE_TRAFFIC_TEST_STATUS_CODE:-503}"
fi
if [ -n "$dump_header" ]; then
  printf 'HTTP/1.1 200 OK\r\nX-Request-ID: 0123456789abcdef0123456789abcdef\r\n\r\n' >"$dump_header"
fi
STUB

cat >"${stub_dir}/ssh" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf 'ssh %s\n' "$*" >>"$FLARE_TRAFFIC_TEST_LOG"
STUB

cat >"${stub_dir}/sleep" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
exit 0
STUB
chmod 0700 "${stub_dir}/curl" "${stub_dir}/ssh" "${stub_dir}/sleep"

PATH="${stub_dir}:$PATH" \
  I_OWN_THIS_TARGET=yes \
  FLARE_LAB_TARGET=http://lab.example \
  FLARE_LAB_ALLOWED_HOST=lab.example \
  DEMO_LOGIN_USERNAME=demo-user \
  DEMO_LOGIN_PASSWORD=demo-password \
  "${ROOT_DIR}/observability/scripts/traffic-normal.sh" >/dev/null
grep -F 'body={"username":"demo-user","password":"demo-password"}' "$FLARE_TRAFFIC_TEST_LOG" >/dev/null
if grep -F '"email"' "$FLARE_TRAFFIC_TEST_LOG" >/dev/null; then
  printf 'Normal traffic contract still sends an email login field.\n' >&2
  exit 1
fi
grep -F 'X-XSRF-TOKEN:' "$FLARE_TRAFFIC_TEST_LOG" >/dev/null

: >"$FLARE_TRAFFIC_TEST_LOG"
PATH="${stub_dir}:$PATH" \
  I_OWN_THIS_TARGET=yes \
  FLARE_LAB_TARGET=http://lab.example \
  FLARE_LAB_ALLOWED_HOST=lab.example \
  "${ROOT_DIR}/observability/scripts/traffic-abnormal-owned-lab.sh" >/dev/null
grep -F '/assets/flare-lab-missing-1.css' "$FLARE_TRAFFIC_TEST_LOG" >/dev/null
if grep -F '/api/lab-missing-' "$FLARE_TRAFFIC_TEST_LOG" >/dev/null; then
  printf '404 traffic contract still routes through an authenticated API path.\n' >&2
  exit 1
fi
grep -F 'file=..%2F..%2Fetc%2Fpasswd' "$FLARE_TRAFFIC_TEST_LOG" >/dev/null
if grep -F '/%2e%2e%2fetc%2fpasswd' "$FLARE_TRAFFIC_TEST_LOG" >/dev/null; then
  printf 'Traversal contract still uses the path form rejected before the custom access log.\n' >&2
  exit 1
fi

: >"$FLARE_TRAFFIC_TEST_LOG"
PATH="${stub_dir}:$PATH" \
  I_OWN_THIS_TARGET=yes \
  WEB_HOST=ubuntu@lab.example \
  FLARE_LAB_TARGET=http://lab.example \
  FLARE_LAB_ALLOWED_HOST=lab.example \
  "${ROOT_DIR}/observability/scripts/traffic-5xx-owned-aws.sh" >/dev/null
[ "$(grep -c 'aws_5xx_probe=' "$FLARE_TRAFFIC_TEST_LOG")" -eq 6 ]
grep -F 'stop -t 30 app' "$FLARE_TRAFFIC_TEST_LOG" >/dev/null
grep -F 'up --wait --wait-timeout 180 -d app' "$FLARE_TRAFFIC_TEST_LOG" >/dev/null

: >"$FLARE_TRAFFIC_TEST_LOG"
if PATH="${stub_dir}:$PATH" \
  FLARE_TRAFFIC_TEST_STATUS_CODE=200 \
  I_OWN_THIS_TARGET=yes \
  WEB_HOST=ubuntu@lab.example \
  FLARE_LAB_TARGET=http://lab.example \
  FLARE_LAB_ALLOWED_HOST=lab.example \
  "${ROOT_DIR}/observability/scripts/traffic-5xx-owned-aws.sh" >/dev/null 2>&1; then
  printf 'AWS 5xx contract accepted a non-5xx response.\n' >&2
  exit 1
fi
grep -F 'up --wait --wait-timeout 180 -d app' "$FLARE_TRAFFIC_TEST_LOG" >/dev/null

cat >"${stub_dir}/ssh" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
cat >/dev/null
case "$*" in
  *ubuntu@web.example*aws-soc.py*verify*)
    printf '%s\n' '{"passed":true,"rbac":true}'
    ;;
  *ubuntu@web.example*)
    printf '%s\n' '{"cloud_init":"status: done","services":[{"service":"app","state":"running","health":"healthy"},{"service":"db","state":"running","health":"healthy"},{"service":"filebeat","state":"running","health":"healthy"},{"service":"gateway","state":"running","health":"healthy"},{"service":"nginx","state":"running","health":"healthy"},{"service":"redis","state":"running","health":"healthy"},{"service":"ueba-worker","state":"running","health":"healthy"}],"filebeat_output":true,"gateway_healthy":true,"recovery_loopback":true}'
    ;;
  *ubuntu@monitor.example*)
    printf '%s\n' '{"cloud_init":"status: done","services":[{"service":"elasticsearch","state":"running","health":"healthy"},{"service":"kibana","state":"running","health":"healthy"},{"service":"logstash","state":"running","health":"healthy"}],"elasticsearch_data_mount":true,"cluster_status":"green","access_documents":42,"public_geo_documents":7,"alert_rule_ids":["flare-lab-auth-bruteforce","flare-lab-high-request-rate","flare-lab-high-web-heuristic","flare-lab-scanner-user-agent","flare-lab-server-errors","flare-lab-web-scan-404"],"dashboard_count":3,"detection_rule_count":6}'
    ;;
  *) exit 1 ;;
esac
STUB
cat >"${stub_dir}/terraform" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' '{"website_http_url":{"sensitive":false,"type":"string","value":"http://web.example"}}'
STUB
chmod 0700 "${stub_dir}/ssh" "${stub_dir}/terraform"

evidence_dir="${test_dir}/aws-evidence"
PATH="${stub_dir}:$PATH" \
  FLARE_TRAFFIC_TEST_STATUS_CODE=200 \
  I_OWN_THIS_TARGET=yes \
  WEB_HOST=ubuntu@web.example \
  MONITOR_HOST=ubuntu@monitor.example \
  FLARE_LAB_TARGET=http://web.example \
  FLARE_LAB_ALLOWED_HOST=web.example \
  AWS_EVIDENCE_DIR="$evidence_dir" \
  "${ROOT_DIR}/observability/scripts/verify-aws-lab.sh" >/dev/null
jq -e '.passed==true and .scope=="aws-runtime-smoke" and .full_acceptance==false and .website_http_status==200' \
  "${evidence_dir}/verification.json" >/dev/null
grep -F 'filebeat test output --strict.perms=false --path.data /tmp/aws-acceptance-output-test </dev/null' \
  "${ROOT_DIR}/observability/scripts/verify-aws-lab.sh" >/dev/null
grep -F "' -- \"\$endpoint\" \"\$body\" </dev/null" \
  "${ROOT_DIR}/observability/scripts/verify-aws-lab.sh" >/dev/null
if rg -i 'demo-password|test-csrf-token|authorization:|BEGIN [A-Z ]*PRIVATE KEY' "$evidence_dir" -g '*.json' -g '*.md' >/dev/null; then
  printf 'AWS evidence contract wrote a credential marker.\n' >&2
  exit 1
fi

printf 'Owned traffic and sanitized AWS acceptance contracts passed.\n'
