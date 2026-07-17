#!/usr/bin/env bash
set -Eeuo pipefail

# Generate the lab PKI, one-secret-per-file credentials and Elastic product
# keystores. A complete set is reusable; a partial set is never overwritten.
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
SECRETS_DIR=${OBSERVABILITY_SECRETS_DIR:-"${ROOT_DIR}/.secrets/observability"}
MONITOR_DIR="${SECRETS_DIR}/monitor"
WEB_DIR="${SECRETS_DIR}/web"
KIBANA_IMAGE='docker.elastic.co/kibana/kibana:9.4.2@sha256:862c968ad7dc3d4e51af83fa30b25c0556b235f54f5a8917284eab7cf322381f'
LOGSTASH_IMAGE='docker.elastic.co/logstash/logstash:9.4.2@sha256:a0664a36744b4767b8648d24d1fa676f92349f24b69302879fcd7da0798b42fd'
FILEBEAT_IMAGE='docker.elastic.co/beats/filebeat:9.4.2@sha256:f2b3bb6a6a02ebfc5f2f91cf8d560522acc4965bdb941f3f1608964cb8544829'

for binary in docker openssl; do
  command -v "$binary" >/dev/null 2>&1 || {
    printf 'Missing required command: %s\n' "$binary" >&2
    exit 1
  }
done

required_files=(
  "${MONITOR_DIR}/elasticsearch.password"
  "${MONITOR_DIR}/kibana-system.password"
  "${MONITOR_DIR}/logstash-internal.password"
  "${MONITOR_DIR}/analyst.password"
  "${MONITOR_DIR}/ca.crt"
  "${MONITOR_DIR}/ca.key"
  "${MONITOR_DIR}/elasticsearch.crt"
  "${MONITOR_DIR}/elasticsearch.key"
  "${MONITOR_DIR}/logstash.crt"
  "${MONITOR_DIR}/logstash.key"
  "${MONITOR_DIR}/kibana.keystore"
  "${MONITOR_DIR}/logstash.keystore"
  "${WEB_DIR}/ca.crt"
  "${WEB_DIR}/filebeat-web.crt"
  "${WEB_DIR}/filebeat-web.key"
)

secure_filebeat_key() {
  # Bind mounts preserve numeric ownership. GitHub-hosted runners are not UID
  # 1000, while the unprivileged Filebeat container deliberately is. Apply the
  # ownership inside a tightly constrained container so the key can stay 0600.
  docker run --rm --network none --read-only --cap-drop ALL \
    --cap-add CHOWN --cap-add FOWNER --user 0:0 \
    -v "${WEB_DIR}/filebeat-web.key:/filebeat-web.key" \
    --entrypoint sh "$FILEBEAT_IMAGE" \
    -c 'chown 1000:1000 /filebeat-web.key && chmod 0600 /filebeat-web.key'
}

existing=0
for path in "${required_files[@]}"; do
  [ ! -e "$path" ] || existing=$((existing + 1))
done
if [ "$existing" -eq "${#required_files[@]}" ]; then
  chmod 0700 "$SECRETS_DIR" "$MONITOR_DIR" "$WEB_DIR"
  chmod 0600 "${MONITOR_DIR}"/*.password "${MONITOR_DIR}"/*.key \
    "${MONITOR_DIR}"/*.keystore
  secure_filebeat_key
  printf 'Observability secrets already exist and were left unchanged in %s.\n' "$SECRETS_DIR"
  exit 0
fi
if [ "$existing" -ne 0 ] || [ -e "$MONITOR_DIR" ] || [ -e "$WEB_DIR" ]; then
  printf 'Refusing to overwrite an incomplete observability secret set in %s.\n' "$SECRETS_DIR" >&2
  printf 'Rotation: stop the stack, archive only non-secret evidence, remove the entire directory, then rerun bootstrap.\n' >&2
  exit 1
fi

umask 077
install -d -m 0700 "$SECRETS_DIR" "$MONITOR_DIR" "$WEB_DIR"
cleanup() {
  rm -rf "${MONITOR_DIR}/.kibana-config" "${MONITOR_DIR}/.logstash-config"
}
trap cleanup EXIT

random_value() {
  # 192 bits, fixed-length, shell-safe and accepted by all three products.
  openssl rand -hex 24
}

write_secret() {
  local path=$1
  random_value >"$path"
  chmod 0600 "$path"
}

for name in elasticsearch kibana-system logstash-internal analyst; do
  write_secret "${MONITOR_DIR}/${name}.password"
done

create_certificate() {
  local name=$1
  local usage=$2
  local san=$3
  local key_path="${MONITOR_DIR}/${name}.key"
  local csr_path="${MONITOR_DIR}/${name}.csr"
  local cert_path="${MONITOR_DIR}/${name}.crt"
  local extensions="${MONITOR_DIR}/${name}.ext"

  openssl genrsa -out "$key_path" 4096 >/dev/null 2>&1
  openssl req -new -key "$key_path" -out "$csr_path" -subj "/CN=${name}" >/dev/null 2>&1
  {
    printf 'basicConstraints=critical,CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature,keyEncipherment\n'
    printf 'extendedKeyUsage=%s\n' "$usage"
    printf 'subjectAltName=%s\n' "$san"
  } >"$extensions"
  openssl x509 -req -sha256 -days 825 -in "$csr_path" \
    -CA "${MONITOR_DIR}/ca.crt" -CAkey "${MONITOR_DIR}/ca.key" -CAcreateserial \
    -out "$cert_path" -extfile "$extensions" >/dev/null 2>&1
  rm -f "$csr_path" "$extensions"
  chmod 0600 "$key_path"
  chmod 0644 "$cert_path"
}

openssl genrsa -out "${MONITOR_DIR}/ca.key" 4096 >/dev/null 2>&1
openssl req -x509 -new -sha256 -days 1825 -key "${MONITOR_DIR}/ca.key" \
  -out "${MONITOR_DIR}/ca.crt" -subj '/CN=Flare AWS ELK Lab CA' >/dev/null 2>&1
chmod 0600 "${MONITOR_DIR}/ca.key"
chmod 0644 "${MONITOR_DIR}/ca.crt"

create_certificate elasticsearch 'serverAuth,clientAuth' 'DNS:elasticsearch,DNS:localhost,IP:127.0.0.1,IP:10.20.10.20'
create_certificate logstash 'serverAuth' 'DNS:logstash,DNS:localhost,IP:127.0.0.1,IP:10.20.10.20'

openssl genrsa -out "${WEB_DIR}/filebeat-web.key" 4096 >/dev/null 2>&1
openssl req -new -key "${WEB_DIR}/filebeat-web.key" -out "${WEB_DIR}/filebeat-web.csr" \
  -subj '/CN=filebeat-web' >/dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=clientAuth' >"${WEB_DIR}/filebeat-web.ext"
openssl x509 -req -sha256 -days 825 -in "${WEB_DIR}/filebeat-web.csr" \
  -CA "${MONITOR_DIR}/ca.crt" -CAkey "${MONITOR_DIR}/ca.key" -CAcreateserial \
  -out "${WEB_DIR}/filebeat-web.crt" -extfile "${WEB_DIR}/filebeat-web.ext" >/dev/null 2>&1
cp "${MONITOR_DIR}/ca.crt" "${WEB_DIR}/ca.crt"
rm -f "${WEB_DIR}/filebeat-web.csr" "${WEB_DIR}/filebeat-web.ext"
chmod 0600 "${WEB_DIR}/filebeat-web.key"
chmod 0644 "${WEB_DIR}/filebeat-web.crt" "${WEB_DIR}/ca.crt"
secure_filebeat_key

create_kibana_keystore() {
  local config_dir="${MONITOR_DIR}/.kibana-config"
  install -d -m 0700 "$config_dir"
  docker run --rm --user "$(id -u):$(id -g)" -e KBN_PATH_CONF=/keystore \
    -v "${config_dir}:/keystore" --entrypoint /usr/share/kibana/bin/kibana-keystore \
    "$KIBANA_IMAGE" create
  local key value
  while IFS='|' read -r key value; do
    printf '%s' "$value" | docker run --rm -i --user "$(id -u):$(id -g)" \
      -e KBN_PATH_CONF=/keystore -v "${config_dir}:/keystore" \
      --entrypoint /usr/share/kibana/bin/kibana-keystore "$KIBANA_IMAGE" add "$key" --stdin
  done <<EOF
elasticsearch.password|$(<"${MONITOR_DIR}/kibana-system.password")
xpack.encryptedSavedObjects.encryptionKey|$(random_value)
xpack.security.encryptionKey|$(random_value)
xpack.reporting.encryptionKey|$(random_value)
EOF
  mv "${config_dir}/kibana.keystore" "${MONITOR_DIR}/kibana.keystore"
  chmod 0600 "${MONITOR_DIR}/kibana.keystore"
}

create_logstash_keystore() {
  local config_dir="${MONITOR_DIR}/.logstash-config"
  install -d -m 0700 "$config_dir"
  install -m 0600 "${ROOT_DIR}/observability/logstash/config/logstash.yml" "${config_dir}/logstash.yml"
  printf 'y\n' | docker run --rm -i --user "$(id -u):$(id -g)" -v "${config_dir}:/keystore" \
    --entrypoint /usr/share/logstash/bin/logstash-keystore "$LOGSTASH_IMAGE" \
    --path.settings /keystore create
  printf '%s' "$(<"${MONITOR_DIR}/logstash-internal.password")" | \
    docker run --rm -i --user "$(id -u):$(id -g)" -v "${config_dir}:/keystore" \
      --entrypoint /usr/share/logstash/bin/logstash-keystore "$LOGSTASH_IMAGE" \
      --path.settings /keystore add LOGSTASH_INTERNAL_PASSWORD --stdin
  mv "${config_dir}/logstash.keystore" "${MONITOR_DIR}/logstash.keystore"
  chmod 0600 "${MONITOR_DIR}/logstash.keystore"
}

create_kibana_keystore
create_logstash_keystore

printf 'Generated observability PKI, password files and product keystores under %s.\n' "$SECRETS_DIR"
printf 'Copy only %s to Web; never copy the CA key or Monitor password files.\n' "$WEB_DIR"
