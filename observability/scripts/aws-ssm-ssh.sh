#!/usr/bin/env bash
# SSH over the existing IAM-authenticated SSM tunnel. No inbound rule changes.
set -euo pipefail

role="${1:-}"
case "$role" in
  web|monitor) shift ;;
  *) printf 'Usage: %s web|monitor [remote-command ...]\n' "$0" >&2; exit 2 ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "$script_dir/../.." && pwd)"
terraform_bin="${FLARE_TERRAFORM_BIN:-terraform}"
key_file="${FLARE_SSH_KEY_FILE:-/home/quan/.ssh/flare-aws-elk-lab}"

if [[ -n "${SSM_PLUGIN_BIN_DIR:-}" ]]; then
  [[ -x "$SSM_PLUGIN_BIN_DIR/session-manager-plugin" ]] || {
    printf 'SSM_PLUGIN_BIN_DIR must contain a verified executable plugin.\n' >&2; exit 2;
  }
  export PATH="$SSM_PLUGIN_BIN_DIR:$PATH"
fi
command -v session-manager-plugin >/dev/null || {
  printf 'Install/verify the official AWS Session Manager plugin first.\n' >&2; exit 2;
}
command -v aws >/dev/null
command -v "$terraform_bin" >/dev/null
[[ -f "$key_file" ]] || { printf 'SSH key file is unavailable.\n' >&2; exit 2; }

instance_id="$("$terraform_bin" -chdir="$project_dir/terraform" output -raw "${role}_instance_id")"
host_key_alias="$("$terraform_bin" -chdir="$project_dir/terraform" output -raw "${role}_elastic_ip")"
[[ "$instance_id" =~ ^i-[a-f0-9]{17}$ ]] || { printf 'Invalid Terraform instance output.\n' >&2; exit 2; }
[[ "$host_key_alias" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  printf 'Invalid Terraform host-key alias.\n' >&2; exit 2;
}
export AWS_PROFILE="${AWS_PROFILE:-flare-lab}"
export AWS_REGION="${AWS_REGION:-ap-southeast-1}"
export AWS_DEFAULT_REGION="$AWS_REGION"

# Reuse the already verified EC2 EIP host key. Never accept a replacement key.
# Explicit task configuration avoids unrelated system/user ProxyCommand rules;
# default known_hosts still applies and strict key verification remains enabled.
exec ssh -F /dev/null -i "$key_file" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=30 \
  -o StrictHostKeyChecking=yes -o "HostKeyAlias=$host_key_alias" \
  -o 'ProxyCommand=aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters portNumber=%p' \
  "ubuntu@$instance_id" "$@"
