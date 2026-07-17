#!/bin/sh
set -eu

# Docker-based smoke test intended for local use and CI. It exercises the
# rendered nginx configuration instead of only checking the source template.
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

IMAGE=${NGINX_TEST_IMAGE:-flare-nginx-hardening-test}
SUFFIX=$$
NETWORK="flare-nginx-hardening-${SUFFIX}"
MOCK_APP="flare-nginx-hardening-app-${SUFFIX}"
WEB="flare-nginx-hardening-web-${SUFFIX}"
TRUSTED_WEB="flare-nginx-trusted-web-${SUFFIX}"

cleanup() {
  docker rm -f "$TRUSTED_WEB" "$WEB" "$MOCK_APP" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker build --tag "$IMAGE" --file nginx/Dockerfile . >/dev/null
if docker run --rm -e 'NGINX_TRUSTED_PROXY_CIDR=0.0.0.0/0' "$IMAGE" nginx -t >/dev/null 2>&1; then
  printf '%s\n' 'Nginx accepted an unsafe trusted proxy CIDR' >&2
  exit 1
fi
docker network create "$NETWORK" >/dev/null
docker run -d --rm --name "$MOCK_APP" --network "$NETWORK" --network-alias app nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10 >/dev/null
docker run -d --rm --name "$WEB" --network "$NETWORK" -p 127.0.0.1::80 "$IMAGE" >/dev/null
TRUSTED_PROXY_CIDR=$(docker network inspect "$NETWORK" --format '{{(index .IPAM.Config 0).Subnet}}')
docker run -d --rm --name "$TRUSTED_WEB" --network "$NETWORK" --network-alias trusted-web \
  -e "NGINX_TRUSTED_PROXY_CIDR=${TRUSTED_PROXY_CIDR}" "$IMAGE" >/dev/null

PORT=$(docker port "$WEB" 80/tcp | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | head -n 1)
BASE_URL="http://127.0.0.1:${PORT}"

headers() {
  attempt=1
  while [ "$attempt" -le 10 ]; do
    if response=$(curl --connect-timeout 2 --max-time 5 --silent --show-error --dump-header - --output /dev/null "$@" 2>/dev/null); then
      printf '%s\n' "$response" | tr -d '\r'
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  printf '%s\n' 'Nginx did not become ready in time' >&2
  return 1
}

assert_security_headers() {
  response=$1
  target=$2
  for header in Content-Security-Policy Strict-Transport-Security X-Frame-Options X-Content-Type-Options Referrer-Policy Permissions-Policy; do
    header_count=$(printf '%s\n' "$response" | grep -ci "^${header}:" || true)
    if [ "$header_count" -eq 0 ]; then
      printf 'Missing %s on %s\n' "$header" "$target" >&2
      exit 1
    fi
    if [ "$header_count" -ne 1 ]; then
      printf 'Duplicate %s on %s\n' "$header" "$target" >&2
      exit 1
    fi
  done

  if ! printf '%s\n' "$response" | grep -qi "^Content-Security-Policy:.*frame-ancestors 'none'"; then
    printf 'CSP frame-ancestors policy is missing on %s\n' "$target" >&2
    exit 1
  fi
  if ! printf '%s\n' "$response" | grep -qi '^Strict-Transport-Security:.*max-age='; then
    printf 'HSTS max-age is missing on %s\n' "$target" >&2
    exit 1
  fi
}

root_response=$(headers -H 'Host: localhost' "${BASE_URL}/")
index_response=$(headers -H 'Host: localhost' "${BASE_URL}/index.html")
asset_response=$(headers -H 'Host: localhost' "${BASE_URL}/assets/svg/twitter.svg")
api_response=$(headers -H 'Host: localhost' "${BASE_URL}/api/health")
spoof_response=$(headers -H 'Host: flarefitness.site' -H 'X-Forwarded-Proto: https' "${BASE_URL}/")
trusted_proxy_response=''
attempt=1
while [ "$attempt" -le 10 ]; do
  if trusted_proxy_response=$(docker exec "$MOCK_APP" wget -S -O /dev/null \
    --header='Host: flarefitness.site' --header='X-Forwarded-Proto: https' http://trusted-web/ 2>&1); then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done

assert_security_headers "$root_response" /
assert_security_headers "$index_response" /index.html
assert_security_headers "$asset_response" /assets/svg/twitter.svg
assert_security_headers "$api_response" /api/health
assert_security_headers "$spoof_response" HTTPS-redirect

if ! printf '%s\n' "$spoof_response" | grep -q '^HTTP/.* 301'; then
  printf 'An untrusted X-Forwarded-Proto header bypassed the HTTPS redirect\n' >&2
  exit 1
fi

if ! printf '%s\n' "$spoof_response" | grep -qi '^Location: https://flarefitness.site/'; then
  printf 'HTTPS redirect target is missing or incorrect\n' >&2
  exit 1
fi

if ! printf '%s\n' "$trusted_proxy_response" | grep -q 'HTTP/1.1 200'; then
  printf 'Configured trusted proxy did not preserve HTTPS forwarding\n' >&2
  exit 1
fi

# An unknown Host must reach the default server, which deliberately drops the
# connection with 444 rather than serving the SPA to a Host-header attack.
unknown_host_status=$(curl --connect-timeout 2 --max-time 5 --silent --output /dev/null \
  --write-out '%{http_code}' -H 'Host: unknown-host.invalid' "${BASE_URL}/" || true)
if [ "$unknown_host_status" != '000' ]; then
  printf 'Unknown Host was not rejected by the default Nginx server\n' >&2
  exit 1
fi

# Exercise the JSON access-log contract with a sensitive query and spoofed
# forwarding header. The direct client must not control source.ip and query
# values must never reach the log.
observability_response=$(headers -H 'Host: localhost' \
  -H 'X-Forwarded-For: 198.51.100.77' \
  "${BASE_URL}/?email=secret%40example.test&page=1")
trace_id=$(printf '%s\n' "$observability_response" | awk 'tolower($1) == "x-request-id:" { print $2; exit }')
if [ -z "$trace_id" ]; then
  printf 'Nginx did not return X-Request-ID\n' >&2
  exit 1
fi
if [ "$(printf '%s\n' "$observability_response" | awk 'tolower($1) == "x-request-id:" { count += 1 } END { print count + 0 }')" -ne 1 ]; then
  printf 'Nginx returned duplicate X-Request-ID headers\n' >&2
  exit 1
fi

access_event=$(docker exec "$WEB" sh -c 'tail -n 1 /var/log/nginx/access.json.log')
if ! printf '%s' "$access_event" | jq -e . >/dev/null; then
  printf 'Nginx access event is not valid JSON\n' >&2
  exit 1
fi
if [ "$(printf '%s' "$access_event" | jq -r '."trace.id"')" != "$trace_id" ]; then
  printf 'Nginx access event trace.id does not match X-Request-ID\n' >&2
  exit 1
fi
if [ "$(printf '%s' "$access_event" | jq -r '."source.ip"')" = '198.51.100.77' ]; then
  printf 'An untrusted X-Forwarded-For value reached source.ip\n' >&2
  exit 1
fi
for assertion in \
  '."@timestamp" | type == "string"' \
  '."http.request.method" == "GET"' \
  '."http.response.status_code" | type == "number"' \
  '."url.path" == "/"' \
  '."url.query" == "[REDACTED]"' \
  '."url.original" == "/?[REDACTED]"' \
  '."event.duration_seconds" | type == "number" and . >= 0'; do
  if ! printf '%s' "$access_event" | jq -e "$assertion" >/dev/null; then
    printf 'Nginx access event failed contract assertion: %s\n' "$assertion" >&2
    exit 1
  fi
done
if printf '%s' "$access_event" | grep -Fqi 'secret%40example.test'; then
  printf 'Sensitive query value leaked into the Nginx access log\n' >&2
  exit 1
fi

# Nginx detects an encoded SQLi signal before masking the query, so Kibana can
# alert without retaining the payload in Nginx/Filebeat/Elasticsearch.
headers -H 'Host: localhost' "${BASE_URL}/?q=%27%20union%20select%20lab" >/dev/null
heuristic_event=$(docker exec "$WEB" sh -c 'tail -n 1 /var/log/nginx/access.json.log')
if ! printf '%s' "$heuristic_event" | jq -e \
  '."url.query" == "[REDACTED]" and ."url.original" == "/?[REDACTED]" and
   ."flare.detection.type" == "sql_injection_signal" and
   ."flare.detection.severity" == "high" and
   ."flare.detection.reason" == "URL matched a SQL injection heuristic"' >/dev/null; then
  printf 'Encoded SQLi heuristic/redaction contract failed\n' >&2
  exit 1
fi
if printf '%s' "$heuristic_event" | grep -Fqi 'union%20select'; then
  printf 'Heuristic query payload leaked into the Nginx access log\n' >&2
  exit 1
fi

if printf '%s\n%s\n%s\n%s\n' "$index_response" "$asset_response" "$api_response" "$spoof_response" | grep -qi '^Server: nginx/'; then
  printf 'Nginx version is exposed in a Server header\n' >&2
  exit 1
fi

printf '%s\n' 'Nginx hardening checks passed.'
