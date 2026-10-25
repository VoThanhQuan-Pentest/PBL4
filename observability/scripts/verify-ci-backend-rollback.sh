#!/usr/bin/env bash
set -Eeuo pipefail

# Rehearse only the backend binary transition against disposable synthetic data.
# Never restore a database or downgrade the gateway/policy schema.
[[ "${GITHUB_ACTIONS:-}" == true && "${COMPOSE_PROJECT_NAME:-}" =~ ^pbl4-observability-runtime-[0-9]+-[0-9]+$ ]] || {
  printf 'Rollback rehearsal requires the disposable CI runtime project.\n' >&2; exit 2;
}
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || { printf 'A full candidate SHA is required.\n' >&2; exit 2; }
[[ $# == 1 && -f "$1/backend/Dockerfile" ]] || { printf 'Supply the checked-out baseline source directory.\n' >&2; exit 2; }
ROOT=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
# Match local-lab.sh when recreating the writer. Child-script exports do not
# survive into this process; defaults point outside the checkout and assume
# GID 1000, while hosted runners own the private 0640 files as another group.
export OBSERVABILITY_ROOT_DIR="$ROOT"
export FILEBEAT_CERTS_DIR="$ROOT/.secrets/observability/web"
UEBA_OPERATOR_GID=$(id -g)
export UEBA_OPERATOR_GID
baseline_source=$(realpath "$1")
baseline_sha=$(git -C "$baseline_source" rev-parse HEAD)
[[ "$baseline_sha" == d7bee8aaddab809e05b010deca69433f9c85d835 ]] || {
  printf 'Unexpected baseline commit.\n' >&2; exit 2;
}
compose_args=(--env-file .env.e2e.example --project-name "$COMPOSE_PROJECT_NAME" --profile observability
  -f docker-compose.yml -f docker-compose.e2e.yml -f observability/docker-compose.monitor.yml
  -f observability/docker-compose.local.yml)
compose() { docker compose "${compose_args[@]}" "$@"; }
mapfile -t app_ids < <(compose ps -q app)
[[ ${#app_ids[@]} == 1 && -n "${app_ids[0]}" ]] || { printf 'Expected exactly one candidate writer.\n' >&2; exit 1; }
candidate_image=$(docker inspect --format '{{.Image}}' "${app_ids[0]}")
[[ "$candidate_image" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
temporary=$(mktemp -d "${RUNNER_TEMP:?}/flare-ci-rollback.XXXXXXXX")
candidate_tag="flare-ci-rollback-candidate:$GITHUB_SHA"
baseline_tag="flare-ci-rollback-baseline:$baseline_sha"
docker tag "$candidate_image" "$candidate_tag"
printf 'services:\n  app:\n    image: %s\n' "$candidate_tag" > "$temporary/candidate.yml"
printf 'services:\n  app:\n    image: %s\n' "$baseline_tag" > "$temporary/baseline.yml"
changed=false
restore_candidate() {
  compose -f "$temporary/candidate.yml" up --wait --wait-timeout 180 -d --no-deps \
    --force-recreate --no-build --pull never app || return
  mapfile -t restored < <(compose ps -q app)
  [[ ${#restored[@]} == 1 ]] && [[ "$(docker inspect --format '{{.Image}}' "${restored[0]}")" == "$candidate_image" ]]
}
cleanup() {
  status=$?
  trap - EXIT
  if [[ "$changed" == true ]]; then
    restore_candidate || { printf 'Candidate restoration failed in isolated CI project.\n' >&2; status=1; }
  fi
  rm -rf -- "$temporary"
  exit "$status"
}
trap cleanup EXIT
fingerprint_accounts() {
  # Hash inside the disposable DB container; never export account rows or passwords.
  # shellcheck disable=SC2016
  compose exec -T db bash -o pipefail -ceu 'export MYSQL_PWD="$MYSQL_PASSWORD"; mysqldump --no-tablespaces --no-create-info --skip-comments --compact --order-by-primary --skip-extended-insert --set-gtid-purged=OFF -u "$MYSQL_USER" "$MYSQL_DATABASE" tbl_nguoi_dung | sha256sum' | awk '{print $1}'
}
fingerprint_migrations() {
  # The variables below expand only inside the disposable DB container.
  # shellcheck disable=SC2016
  compose exec -T db bash -o pipefail -ceu 'export MYSQL_PWD="$MYSQL_PASSWORD"; mysql -N -u "$MYSQL_USER" "$MYSQL_DATABASE" -e "SELECT version,checksum FROM flyway_schema_history ORDER BY installed_rank" | sha256sum' | awk '{print $1}'
}
probe() {
  curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8088/api/health | jq -e '.status=="UP"' >/dev/null
  curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8088/api/products | jq -e 'type=="object" or type=="array"' >/dev/null
}
# Test cookies stay in this private temporary directory and are never artifacts.
session_probe() {
  CI_SESSION_MODE="$1" CI_COOKIE_FILE="$temporary/session.cookies" python3 - <<'PY'
import http.cookiejar, json, os, urllib.error, urllib.request
mode = os.environ['CI_SESSION_MODE']
jar = http.cookiejar.LWPCookieJar(os.environ['CI_COOKIE_FILE'])
if mode == 'verify-candidate':
    jar.load(ignore_discard=True, ignore_expires=True)
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
def request(path, method='GET', body=None, csrf=None, expected=200):
    headers = {'User-Agent': 'Flare-CI-Rollback-Session'}
    if csrf is not None: headers['X-XSRF-TOKEN'] = csrf
    if body is not None: headers['Content-Type'] = 'application/json'
    req = urllib.request.Request('http://127.0.0.1:8088/api/' + path,
        data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
    try:
        response = client.open(req, timeout=10)
    except urllib.error.HTTPError as error:
        if error.code == expected:
            error.close()
            return None
        raise RuntimeError('Unexpected HTTP status in the isolated session probe') from None
    with response:
        if response.status != expected: raise RuntimeError('Unexpected session response status')
        raw = response.read(65537)
        if len(raw) > 65536: raise RuntimeError('Session response exceeded its size limit')
        return json.loads(raw) if raw else None
csrf = request('auth/csrf')['token']
if mode in {'warmup', 'save-baseline'}:
    # Public E2E fixtures only. Warm up any normal legacy-hash upgrade before
    # the protected-state fingerprint, without changing the credential itself.
    request('auth/login', 'POST', {'username': 'e2e_customer', 'password': 'CustomerE2E#1'}, csrf)
if request('auth/me')['username'] != 'e2e_customer':
    raise RuntimeError('Baseline session did not identify the expected synthetic customer')
if mode == 'save-baseline':
    jar.save(ignore_discard=True, ignore_expires=True)
    os.chmod(jar.filename, 0o600)
else:
    csrf = request('auth/csrf')['token']
    request('auth/logout', 'POST', {}, csrf, expected=204)
    request('auth/me', expected=401)
PY
}
session_probe warmup
accounts_before=$(fingerprint_accounts)
migrations_before=$(fingerprint_migrations)
[[ "$accounts_before" =~ ^[0-9a-f]{64}$ && "$migrations_before" =~ ^[0-9a-f]{64}$ ]] || exit 1
docker build --tag "$baseline_tag" "$baseline_source/backend"
changed=true
compose -f "$temporary/baseline.yml" up --wait --wait-timeout 180 -d --no-deps \
  --force-recreate --no-build --pull never app
probe
session_probe save-baseline
restore_candidate
changed=false
probe
session_probe verify-candidate
[[ "$(fingerprint_accounts)" == "$accounts_before" && "$(fingerprint_migrations)" == "$migrations_before" ]] || {
  printf 'Protected synthetic accounts or migration checksums changed.\n' >&2; exit 1;
}
export candidate_image baseline_sha
python3 - <<'PY'
import json, os
from pathlib import Path
Path('observability/runtime/ci-rollback-result.json').write_text(json.dumps({
    'status': 'CI_BACKEND_ROLLBACK_PASS', 'baseline_sha': os.environ['baseline_sha'],
    'candidate_image': os.environ['candidate_image'], 'candidate_restored': True,
    'baseline_session_reused_and_revoked_by_candidate': True,
    'account_and_migration_parity': True, 'database_restored': False,
    'gateway_downgraded': False, 'live_stack_modified': False}, indent=2) + '\n')
PY
printf 'Backend baseline/candidate transition passed with protected synthetic state unchanged.\n'
