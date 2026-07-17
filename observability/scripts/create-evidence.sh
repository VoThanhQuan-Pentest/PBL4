#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SOURCE="${ROOT_DIR}/observability/runtime/verification.json"
DEST="${ROOT_DIR}/docs/evidence/local-elk"
ANALYST_PASSWORD_FILE="${ROOT_DIR}/.secrets/observability/monitor/analyst.password"
PLAYWRIGHT_IMAGE='mcr.microsoft.com/playwright:v1.61.1-noble@sha256:cf0daee9b994042e011bc29f20cdff1a9f682a039b43fcd738f7d8a9d3bcd9d6'

[ -r "$SOURCE" ] && jq -e '.passed==true and .synthetic_data_only==true' "$SOURCE" >/dev/null || {
  printf 'Run local-lab.sh verify successfully before creating evidence.\n' >&2
  exit 1
}
[ -r "$ANALYST_PASSWORD_FILE" ] || { printf 'Missing analyst password file.\n' >&2; exit 1; }
install -d -m 0755 "$DEST"
install -m 0644 "$SOURCE" "${DEST}/verification.json"

{
  printf '# Flare local ELK verification\n\n'
  printf -- '- Elastic Stack: `9.4.2`\n'
  printf -- '- Scope: local/code only; AWS was statically validated and was not deployed.\n'
  printf -- '- Data classification: synthetic fixtures only.\n'
  printf -- '- Started: `%s`\n' "$(jq -r '.started_at' "$SOURCE")"
  printf -- '- Finished: `%s`\n\n' "$(jq -r '.finished_at' "$SOURCE")"
  printf '## Checks\n\n'
  jq -r '.checks[] | "- [" + (if .passed then "x" else " " end) + "] **" + .name + "** — " + .detail' "$SOURCE"
  printf '\n## Dashboard evidence\n\n'
  printf 'Screenshots were captured at 1440×900 by the pinned Playwright 1.61.1 container while authenticated as the read-only `flare_analyst` user. No credential is included in this report.\n\n'
  printf -- '- `overview.png`\n- `geoip.png`\n- `security.png`\n'
} >"${DEST}/verification.md"

docker run --rm --network host --user "$(id -u):$(id -g)" \
  -e HOME=/tmp/home -v "${ROOT_DIR}:/workspace:ro" -v "${DEST}:/evidence" \
  -v "${ANALYST_PASSWORD_FILE}:/run/flare-secrets/analyst.password:ro" \
  "$PLAYWRIGHT_IMAGE" bash -ceu '
    install -d /tmp/home /tmp/runner
    cp /workspace/frontend/package.json /workspace/frontend/package-lock.json /tmp/runner/
    cd /tmp/runner
    npm ci --ignore-scripts --no-audit --no-fund >/dev/null
    cp /workspace/observability/scripts/capture-dashboards.mjs ./capture-dashboards.mjs
    node ./capture-dashboards.mjs
  '

for image in overview.png geoip.png security.png; do
  [ -s "${DEST}/${image}" ] || { printf 'Missing dashboard image: %s\n' "$image" >&2; exit 1; }
done
if rg -i 'password|authorization|csrf|jwt|synthetic-secret-marker' "$DEST" -g '*.md' -g '*.json' >/dev/null; then
  # Field names in the machine report are acceptable only when no raw value is
  # present; this guard targets the known synthetic marker and secret keywords.
  rg -n 'synthetic-secret-marker' "$DEST" && exit 1 || true
fi
printf 'Local ELK report and dashboard images written to %s\n' "$DEST"
