#!/usr/bin/env bash
set -Eeuo pipefail

[ "$#" -eq 1 ] || { printf 'Usage: %s APPLICATION_IMAGE\n' "$0" >&2; exit 2; }
binary="$1/bin/FlareSecurityMonitor"
[ -x "$binary" ] || { printf 'Packaged executable is missing.\n' >&2; exit 2; }
command -v xdotool >/dev/null
smoke_dir=$(mktemp -d)
app_pid=''
cleanup() {
  status=$?
  trap - EXIT
  if [ -n "$app_pid" ] && kill -0 "$app_pid" 2>/dev/null; then
    kill "$app_pid" 2>/dev/null || true
    wait "$app_pid" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ]; then cat "$smoke_dir/application.log" >&2; fi
  rm -rf -- "$smoke_dir"
  exit "$status"
}
trap cleanup EXIT
"$binary" >"$smoke_dir/application.log" 2>&1 &
app_pid=$!
shown=false
for ((attempt=0; attempt<30; attempt++)); do
  kill -0 "$app_pid" 2>/dev/null || { printf 'Application exited before showing login.\n' >&2; exit 1; }
  if xdotool search --onlyvisible --pid "$app_pid" --name 'Flare' >/dev/null 2>&1; then
    shown=true
    break
  fi
  sleep 1
done
[ "$shown" = true ] || { printf 'Login window did not appear.\n' >&2; exit 1; }
for ((attempt=0; attempt<12; attempt++)); do
  kill -0 "$app_pid" 2>/dev/null || { printf 'Application crashed after showing login.\n' >&2; exit 1; }
  sleep 1
done
if grep -Eq 'Exception in thread|Error initializing|SIGSEGV|A fatal error has been detected' "$smoke_dir/application.log"; then
  printf 'Fatal application output detected.\n' >&2
  exit 1
fi
printf 'Packaged login displayed and remained alive for 12 seconds.\n'
