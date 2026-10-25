#!/usr/bin/env python3
"""Read-only AWS inventory and cost gate; creates a saved Terraform plan, never applies it."""
import argparse
from datetime import datetime, timezone
from decimal import Decimal
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT_STORAGE_GB_UPPER_BOUND = 140

def estimate(rates):
    fields = ('instance_hour', 'gp3_gb_month', 'snapshot_gb_month', 'ipv4_hour', 'egress_gb')
    values = {name: Decimal(str(rates[name])) for name in fields}
    if any(value < 0 or not value.is_finite() for value in values.values()):
        raise ValueError('Rates must be finite and nonnegative')
    if values['instance_hour'] <= 0 or values['gp3_gb_month'] <= 0 or values['ipv4_hour'] <= 0:
        raise ValueError('Compute, storage and IPv4 prices must be populated')
    tax = Decimal(str(rates['tax_multiplier']))
    if not tax.is_finite() or tax < 1:
        raise ValueError('Tax multiplier must be at least one')
    return ((values['instance_hour'] * 60 + values['gp3_gb_month'] * 140 / 3
             + values['snapshot_gb_month'] * SNAPSHOT_STORAGE_GB_UPPER_BOUND / 3 + values['ipv4_hour'] * 480
             + values['egress_gb'] * 5) * tax).quantize(Decimal('0.01'))

def run_json(args, env):
    result = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True)
    if result.returncode:
        # Do not echo credential_process output or environment values.
        raise RuntimeError(f'{args[0]} {args[1]} failed; check AWS login/permissions locally')
    return json.loads(result.stdout)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rates', type=Path, required=True, help='Rates exported/transcribed from the official calculator; see example')
    p.add_argument('--admin-cidr')
    p.add_argument('--tester-cidr')
    args = p.parse_args()
    rates = json.loads(args.rates.read_text())
    if rates.get('region') != 'ap-southeast-1' or rates.get('instance_type') != 'm7i-flex.large':
        p.error('Price sheet must match ap-southeast-1 / m7i-flex.large')
    checked = datetime.fromisoformat(rates['checked_at'].replace('Z', '+00:00'))
    age = (datetime.now(timezone.utc) - checked).total_seconds()
    if age < 0 or age > 7 * 86400 or not rates.get('source_url', '').startswith((
            'https://calculator.aws/', 'https://pricing.us-east-1.amazonaws.com/', 'https://aws.amazon.com/')):
        p.error('Use dated official pricing evidence no older than seven days')
    cost = estimate(rates)
    if cost > 30:
        p.error(f'Estimated USD {cost} exceeds the USD 30 deployment gate')
    env = dict(os.environ, AWS_PROFILE=os.environ.get('AWS_PROFILE', 'flare-lab'),
               AWS_REGION='ap-southeast-1', AWS_DEFAULT_REGION='ap-southeast-1',
               AWS_EC2_METADATA_DISABLED='true')
    identity = run_json(['aws', 'sts', 'get-caller-identity', '--output', 'json'], env)
    if identity.get('Arn', '').endswith(':root'):
        p.error('Use the configured IAM user/role; root credentials are not accepted for this lab')
    quota = run_json(['aws', 'service-quotas', 'get-service-quota', '--service-code', 'ec2',
                      '--quota-code', 'L-1216C47A', '--output', 'json'], env)['Quota']['Value']
    regional = run_json(['aws', 'ec2', 'describe-instances', '--filters',
                         'Name=instance-state-name,Values=running,pending', '--output', 'json'], env)
    used = 0
    project_used = 0
    for reservation in regional['Reservations']:
        for instance in reservation['Instances']:
            if instance.get('InstanceLifecycle') == 'spot' or instance['InstanceType'][0] not in 'acdhimrtz':
                continue
            cpu = instance['CpuOptions']['CoreCount'] * instance['CpuOptions']['ThreadsPerCore']
            used += cpu
            if any(tag['Key'] == 'Project' and tag['Value'] == 'flare-aws-elk-lab' for tag in instance.get('Tags', [])):
                project_used += cpu
    if used - project_used + 4 > quota:
        p.error('Standard vCPU quota has insufficient headroom for the two-instance lab')
    inventory = {}
    for operation in ('describe-instances', 'describe-volumes', 'describe-addresses', 'describe-vpcs'):
        inventory[operation] = run_json(['aws', 'ec2', operation, '--filters',
            'Name=tag:Project,Values=flare-aws-elk-lab', '--output', 'json'], env)
    offerings = run_json(['aws', 'ec2', 'describe-instance-type-offerings', '--location-type',
        'availability-zone', '--filters', 'Name=instance-type,Values=m7i-flex.large', '--output', 'json'], env)
    zones = run_json(['aws', 'ec2', 'describe-availability-zones', '--filters', 'Name=state,Values=available', '--output', 'json'], env)
    offered = {row['Location'] for row in offerings['InstanceTypeOfferings']}
    eligible = sorted(zone['ZoneName'] for zone in zones['AvailabilityZones'] if zone['ZoneName'] in offered)
    if not eligible:
        p.error('No available AZ offers the selected instance type')
    selected = eligible[0]
    state = subprocess.check_output(['terraform', '-chdir=terraform', 'state', 'list'], cwd=ROOT, env=env, text=True)
    live = [item for row in inventory['describe-instances']['Reservations'] for item in row['Instances']
            if item['State']['Name'] != 'terminated']
    if not state.strip() and (live or inventory['describe-volumes']['Volumes']
                             or inventory['describe-addresses']['Addresses'] or inventory['describe-vpcs']['Vpcs']):
        p.error('Tagged resources exist but state is empty; reconcile/import before planning')
    cidr = args.admin_cidr
    if cidr is None:
        with urllib.request.urlopen('https://checkip.amazonaws.com', timeout=5) as response:
            cidr = response.read(64).decode().strip() + '/32'
    tester = args.tester_cidr or cidr
    for value in (cidr, tester):
        network = ipaddress.IPv4Network(value, strict=True)
        if network.prefixlen != 32 or not network.network_address.is_global:
            p.error('This lab preflight requires public /32 administrator/tester addresses')
    os.umask(0o077)
    dest = ROOT / 'observability/runtime' / ('aws-preflight-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    dest.mkdir(parents=True, exist_ok=False)
    (dest / 'inventory.json').write_text(json.dumps(inventory, indent=2))
    (dest / 'cost.json').write_text(json.dumps(dict(rates, projected_usd=str(cost), account=identity['Account'],
        active_hours_per_instance=30, retained_days=10, admin_cidr=cidr, tester_cidr=tester,
        snapshot_storage_gb_upper_bound=SNAPSHOT_STORAGE_GB_UPPER_BOUND,
        standard_vcpu_quota=quota,
        currently_used_vcpus=used), indent=2))
    for command in (['init', '-input=false'], ['fmt', '-check', '-recursive'], ['validate'], ['test']):
        subprocess.run(['terraform', '-chdir=terraform', *command], cwd=ROOT, env=env, check=True)
    plan = dest / 'reviewed.tfplan'
    subprocess.run(['terraform', '-chdir=terraform', 'plan', '-input=false', '-out=' + str(plan),
        '-var=aws_region=ap-southeast-1', '-var=project_name=flare-aws-elk-lab',
        '-var=web_instance_type=m7i-flex.large', '-var=monitor_instance_type=m7i-flex.large',
        '-var=web_root_volume_gb=40', '-var=monitor_root_volume_gb=20', '-var=monitor_data_volume_gb=80',
        '-var=availability_zone=' + selected,
        '-var=monthly_budget_usd=40', '-var=admin_cidrs=' + json.dumps([cidr]),
        '-var=tester_cidrs=' + json.dumps([tester])], cwd=ROOT, env=env, check=True)
    print(f'Saved plan and private inventory: {dest}. Review before the owner applies it.')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, ArithmeticError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
