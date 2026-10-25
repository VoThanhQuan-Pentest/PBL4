#!/usr/bin/env bash
# Sync host UFW after an in-place Terraform CIDR update. AWS security groups
# remain the network boundary; this script only narrows host ingress further.
set -Eeuo pipefail

usage() {
  printf 'Usage: %s <admin-public-ip/32> <tester-public-ip/32>\n' "$0" >&2
}

if [ "$#" -ne 2 ]; then usage; exit 2; fi
admin_cidr=$1
tester_cidr=$2
python3 - "$admin_cidr" "$tester_cidr" <<'PY'
import ipaddress
import sys

for value in sys.argv[1:]:
    try:
        network = ipaddress.IPv4Network(value, strict=True)
    except ValueError:
        raise SystemExit("CIDRs must be valid IPv4 /32 networks")
    if network.prefixlen != 32 or not network.network_address.is_global:
        raise SystemExit("CIDRs must be public IPv4 /32 addresses")
PY

root_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
terraform_bin=${FLARE_TERRAFORM_BIN:-terraform}
project=${FLARE_AWS_PROJECT_NAME:-flare-aws-elk-lab}
export AWS_PROFILE=${AWS_PROFILE:-flare-lab}
export AWS_REGION=${AWS_REGION:-ap-southeast-1}
export AWS_DEFAULT_REGION=$AWS_REGION
command -v aws >/dev/null
command -v jq >/dev/null
command -v "$terraform_bin" >/dev/null
[[ "$project" =~ ^[a-z][a-z0-9-]{2,40}$ ]] || { printf 'Invalid lab project name.\n' >&2; exit 2; }

web_id=$("$terraform_bin" -chdir="$root_dir/terraform" output -raw web_instance_id)
monitor_id=$("$terraform_bin" -chdir="$root_dir/terraform" output -raw monitor_instance_id)
[[ "$web_id" =~ ^i-[a-f0-9]{17}$ && "$monitor_id" =~ ^i-[a-f0-9]{17}$ ]] || {
  printf 'Terraform instance outputs are invalid.\n' >&2; exit 2;
}

instances=$(aws ec2 describe-instances --region "$AWS_REGION" --instance-ids "$web_id" "$monitor_id" \
  --query 'Reservations[].Instances[].{ID:InstanceId,State:State.Name,PrivateIP:PrivateIpAddress,Tags:Tags}' --output json)
printf '%s' "$instances" | jq -e --arg web "$web_id" --arg monitor "$monitor_id" --arg project "$project" '
  length == 2 and
  any(.[]; .ID==$web and .State=="running" and .PrivateIP=="10.20.10.10" and any(.Tags[]; .Key=="Project" and .Value==$project) and any(.Tags[]; .Key=="Name" and .Value==($project+"-web"))) and
  any(.[]; .ID==$monitor and .State=="running" and .PrivateIP=="10.20.10.20" and any(.Tags[]; .Key=="Project" and .Value==$project) and any(.Tags[]; .Key=="Name" and .Value==($project+"-monitor")))
' >/dev/null || { printf 'Expected running Web and Monitor lab instances were not verified.\n' >&2; exit 1; }

web_sg=$(aws ec2 describe-security-groups --region "$AWS_REGION" \
  --filters "Name=tag:Name,Values=${project}-web-sg" --output json)
web_sg_id=$(printf '%s' "$web_sg" | jq -er 'if (.SecurityGroups|length)==1 then .SecurityGroups[0].GroupId else error("expected exactly one Web security group") end')
printf '%s' "$web_sg" | jq -e --arg admin "$admin_cidr" --arg tester "$tester_cidr" '
  (.SecurityGroups|length)==1 and
  (.SecurityGroups[0] as $sg |
    all([{port:22,cidr:$admin},{port:80,cidr:$tester}][]; . as $expected |
      ([$sg.IpPermissions[] | select(.IpProtocol=="tcp" and .FromPort==$expected.port and .ToPort==$expected.port)] as $rules |
        ($rules|length)==1 and
        ([ $rules[0].IpRanges[]?.CidrIp ]|sort)==[$expected.cidr] and
        ($rules[0].Ipv6Ranges//[])==[] and
        ($rules[0].UserIdGroupPairs//[])==[] and
        ($rules[0].PrefixListIds//[])==[])))
' >/dev/null || { printf 'Web security group does not match the requested /32 allowlists; refusing host firewall changes.\n' >&2; exit 1; }

monitor_sg=$(aws ec2 describe-security-groups --region "$AWS_REGION" \
  --filters "Name=tag:Name,Values=${project}-monitor-sg" --output json)
printf '%s' "$monitor_sg" | jq -e --arg admin "$admin_cidr" --arg web_sg "$web_sg_id" '
  (.SecurityGroups|length)==1 and
  (.SecurityGroups[0] as $sg |
    ([$sg.IpPermissions[] | select(.IpProtocol=="tcp" and .FromPort==22 and .ToPort==22)] as $ssh_rules |
      ($ssh_rules|length)==1 and
      ([ $ssh_rules[0].IpRanges[]?.CidrIp ]|sort)==[$admin] and
      ($ssh_rules[0].Ipv6Ranges//[])==[] and
      ($ssh_rules[0].UserIdGroupPairs//[])==[] and
      ($ssh_rules[0].PrefixListIds//[])==[]) and
    all([5044,9200][]; . as $port |
      ([$sg.IpPermissions[] | select(.IpProtocol=="tcp" and .FromPort==$port and .ToPort==$port)] as $rules |
        ($rules|length)==1 and
        ($rules[0].IpRanges//[])==[] and
        ($rules[0].Ipv6Ranges//[])==[] and
        ([ $rules[0].UserIdGroupPairs[]?.GroupId ]|sort)==[$web_sg] and
        ($rules[0].PrefixListIds//[])==[])))
' >/dev/null || { printf 'Monitor security group does not match the expected admin and Web-only rules; refusing host firewall changes.\n' >&2; exit 1; }

online=$(aws ssm describe-instance-information --region "$AWS_REGION" \
  --filters "Key=InstanceIds,Values=${web_id},${monitor_id}" \
  --query 'InstanceInformationList[?PingStatus==`Online`].InstanceId' --output json)
printf '%s' "$online" | jq -e --arg web "$web_id" --arg monitor "$monitor_id" \
  'length==2 and any(.[]; .==$web) and any(.[]; .==$monitor)' >/dev/null || {
  printf 'Both instances must be online in Systems Manager before changing UFW.\n' >&2; exit 1;
}

web_script_template=$(cat <<'REMOTE'
set -eu
ufw default deny incoming
ufw default allow outgoing
for port in 22/tcp 80/tcp; do
  numbers=$(ufw status numbered | awk -v port="$port" '$3==port && $4=="ALLOW" && $5=="IN" {gsub(/[^0-9]/,"",$2); print $2}' | sort -rn)
  for number in $numbers; do ufw --force delete "$number" >/dev/null; done
done
ufw allow from __ADMIN_CIDR__ to any port 22 proto tcp >/dev/null
ufw allow from __TESTER_CIDR__ to any port 80 proto tcp >/dev/null
ufw --force enable >/dev/null
ufw status verbose >/dev/null
REMOTE
)
web_script=${web_script_template//__ADMIN_CIDR__/$admin_cidr}
web_script=${web_script//__TESTER_CIDR__/$tester_cidr}

monitor_script_template=$(cat <<'REMOTE'
set -eu
ufw default deny incoming
ufw default allow outgoing
for port in 22/tcp 5044/tcp 9200/tcp; do
  numbers=$(ufw status numbered | awk -v port="$port" '$3==port && $4=="ALLOW" && $5=="IN" {gsub(/[^0-9]/,"",$2); print $2}' | sort -rn)
  for number in $numbers; do ufw --force delete "$number" >/dev/null; done
done
ufw allow from __ADMIN_CIDR__ to any port 22 proto tcp >/dev/null
ufw allow from 10.20.10.10 to any port 5044 proto tcp >/dev/null
ufw allow from 10.20.10.10 to any port 9200 proto tcp >/dev/null
ufw --force enable >/dev/null
ufw status verbose >/dev/null
REMOTE
)
monitor_script=${monitor_script_template//__ADMIN_CIDR__/$admin_cidr}

send_and_wait() {
  local role=$1 instance=$2 script=$3 request command_id status attempt
  request=$(jq -cn --arg instance "$instance" --arg script "$script" --arg comment "${project} host firewall sync (${role})" \
    '{InstanceIds:[$instance],DocumentName:"AWS-RunShellScript",TimeoutSeconds:300,Comment:$comment,Parameters:{commands:[$script]}}')
  command_id=$(aws ssm send-command --region "$AWS_REGION" --cli-input-json "$request" \
    --query 'Command.CommandId' --output text)
  [[ "$command_id" =~ ^[0-9a-f-]{36}$ ]] || { printf 'SSM did not return a valid command ID for %s.\n' "$role" >&2; return 1; }
  for attempt in $(seq 1 90); do
    status=$(aws ssm get-command-invocation --region "$AWS_REGION" --command-id "$command_id" \
      --instance-id "$instance" --query Status --output text 2>/dev/null || true)
    case "$status" in
      Success) printf '%s firewall sync: Success\n' "$role"; return 0 ;;
      Failed|TimedOut|Cancelled|Cancelling|Undeliverable|Terminated)
        printf 'SSM firewall sync failed for %s (command %s, status %s).\n' "$role" "$command_id" "$status" >&2
        return 1 ;;
    esac
    sleep 2
  done
  printf 'SSM firewall sync still pending for %s (command %s).\n' "$role" "$command_id" >&2
  return 1
}

send_and_wait web "$web_id" "$web_script"
send_and_wait monitor "$monitor_id" "$monitor_script"
