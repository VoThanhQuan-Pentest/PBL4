#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

command -v mvn >/dev/null 2>&1 || { printf 'Maven is required.\n' >&2; exit 1; }
command -v jpackage >/dev/null 2>&1 || { printf 'A JDK with jpackage is required.\n' >&2; exit 1; }

maven_options=()
case "${1:-}" in
  '') ;;
  --offline) maven_options+=(-o) ;;
  *) printf 'Usage: %s [--offline]\n' "$0" >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { printf 'Too many arguments.\n' >&2; exit 2; }

if [ -L target ]; then
  printf 'Refusing a symlinked package output directory.\n' >&2
  exit 2
fi
install -d -m 0755 target
build_root=$(mktemp -d "$ROOT_DIR/target/package-build.XXXXXXXX")
output_root=$(mktemp -d "$ROOT_DIR/target/dist-release.XXXXXXXX")
cleanup() {
  status=$?
  trap - EXIT
  if [ -d "$build_root/target/surefire-reports" ]; then
    cp -a "$build_root/target/surefire-reports" "$output_root/test-reports"
  fi
  case "${build_root:-}" in
    "$ROOT_DIR/target/package-build."*) rm -rf -- "$build_root" ;;
  esac
  exit "$status"
}
trap cleanup EXIT

# Build in an isolated copy: Maven's clean phase must not erase a previous
# desktop-client/target/dist package or other user-owned build output.
cp -a pom.xml src "$build_root/"
mvn -B -ntp "${maven_options[@]}" -f "$build_root/pom.xml" clean verify
input_dir="$build_root/target/package-input"
install -d -m 0700 "$input_dir"
cp "$build_root/target/flare-security-monitor-0.1.0-SNAPSHOT.jar" "$input_dir/"
cp "$build_root/target/lib/"*.jar "$input_dir/"

jpackage \
  --type app-image \
  --name FlareSecurityMonitor \
  --app-version 0.1.0 \
  --vendor 'Flare Fitness' \
  --description 'SIEM-style client for Flare security incidents' \
  --input "$input_dir" \
  --dest "$output_root" \
  --main-jar flare-security-monitor-0.1.0-SNAPSHOT.jar \
  --main-class com.flarefitness.monitor.Launcher

archive="$output_root/FlareSecurityMonitor-linux.tar.gz"
tar -C "$output_root" -czf "$archive" FlareSecurityMonitor
(
  cd "$output_root"
  sha256sum FlareSecurityMonitor-linux.tar.gz > FlareSecurityMonitor-linux.tar.gz.sha256
)
printf 'Linux application image: %s\n' "$output_root/FlareSecurityMonitor"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'application_image=%s\n' "$output_root/FlareSecurityMonitor" >> "$GITHUB_OUTPUT"
  printf 'application_archive=%s\n' "$archive" >> "$GITHUB_OUTPUT"
fi
