mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["ap-southeast-1a"]
    }
  }

  mock_data "aws_ami" {
    defaults = {
      id = "ami-0123456789abcdef0"
    }
  }
}

variables {
  web_instance_type     = "m7i-flex.large"
  monitor_instance_type = "m7i-flex.large"
  ubuntu_ami_id         = "ami-0123456789abcdef0"
  admin_cidrs           = ["198.51.100.10/32"]
  tester_cidrs          = ["198.51.100.20/32"]
  ssh_public_key        = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILabContractOnlyNotARealKey0000000000000000000 flare-test"
  budget_email          = "team@example.test"
}

run "plan_lab_contract" {
  command = plan

  assert {
    condition     = aws_instance.web.associate_public_ip_address
    error_message = "Web must receive launch-time Internet access because the lab has no NAT gateway and cloud-init runs before the EIP association is guaranteed."
  }

  assert {
    condition     = aws_instance.monitor.associate_public_ip_address
    error_message = "Monitor must receive launch-time Internet access because the lab has no NAT gateway and cloud-init runs before the EIP association is guaranteed."
  }

  assert {
    condition     = aws_instance.web.ami == var.ubuntu_ami_id && aws_instance.monitor.ami == var.ubuntu_ami_id
    error_message = "Both EC2 instances must use the explicitly pinned AMI selected for this plan."
  }

  assert {
    condition     = !aws_instance.web.user_data_replace_on_change && !aws_instance.monitor.user_data_replace_on_change
    error_message = "Firewall CIDR updates must not replace EC2 instances and their root volumes."
  }

  assert {
    condition     = aws_subnet.public.map_public_ip_on_launch == false
    error_message = "The subnet must not assign public IPs to arbitrary future instances; only the two explicit lab instances opt in."
  }

  assert {
    condition = length([
      for rule in aws_security_group.web.ingress : rule
      if rule.from_port == 80 && rule.to_port == 80 && rule.protocol == "tcp" && try(toset(rule.cidr_blocks) == toset(var.tester_cidrs), false)
    ]) == 1
    error_message = "Web HTTP ingress must remain restricted to the named tester CIDRs."
  }

  assert {
    condition = length([
      for rule in aws_security_group.web.ingress : rule
      if rule.from_port == 22 && rule.to_port == 22 && rule.protocol == "tcp" && try(toset(rule.cidr_blocks) == toset(var.admin_cidrs), false)
      ]) == 1 && length([
      for rule in aws_security_group.monitor.ingress : rule
      if rule.from_port == 22 && rule.to_port == 22 && rule.protocol == "tcp" && try(toset(rule.cidr_blocks) == toset(var.admin_cidrs), false)
    ]) == 1
    error_message = "SSH ingress on both EC2 instances must remain restricted to the named administrator CIDRs."
  }

  assert {
    condition = length([
      for rule in aws_security_group.monitor.ingress : rule
      if rule.from_port == 5044 && rule.to_port == 5044 && rule.protocol == "tcp" && try(length(rule.security_groups), 0) == 1 && try(length(rule.cidr_blocks), 0) == 0
    ]) == 1
    error_message = "Logstash ingress must remain restricted to the Web security group."
  }

  assert {
    condition     = aws_ebs_volume.monitor_data.encrypted
    error_message = "The Elasticsearch data volume must remain encrypted."
  }

  assert {
    condition     = aws_instance.web.root_block_device[0].encrypted && aws_instance.monitor.root_block_device[0].encrypted
    error_message = "Both EC2 root volumes must remain encrypted."
  }

  assert {
    condition = length([
      for rule in aws_security_group.monitor.ingress : rule
      if rule.from_port == 9200 && rule.to_port == 9200 && try(length(rule.security_groups), 0) == 1 && try(length(rule.cidr_blocks), 0) == 0
    ]) == 1 && aws_vpc_security_group_egress_rule.web_elasticsearch.cidr_ipv4 == "10.20.10.20/32"
    error_message = "Elasticsearch must be private and reachable only by Web."
  }

  assert {
    condition     = aws_instance.web.instance_type == "m7i-flex.large" && aws_instance.monitor.instance_type == "m7i-flex.large"
    error_message = "The complete lab needs the planned 8 GiB instances."
  }

  assert {
    condition = (
      aws_budgets_budget.monthly.limit_amount == tostring(var.monthly_budget_usd) &&
      length([for filter in aws_budgets_budget.monthly.cost_filter : filter if
      filter.name == "TagKeyValue" && contains(filter.values, format("user:Project$%s", var.project_name))]) == 1 &&
      toset([for item in aws_budgets_budget.monthly.notification : item.threshold if item.notification_type == "ACTUAL"]) == toset([50, 75, 90]) &&
      length([for item in aws_budgets_budget.monthly.notification : item if item.notification_type == "FORECASTED" && item.threshold == 100 && item.threshold_type == "PERCENTAGE"]) == 1 &&
    alltrue([for item in aws_budgets_budget.monthly.notification : item.comparison_operator == "GREATER_THAN" && toset(item.subscriber_email_addresses) == toset([var.budget_email])]))
    error_message = "The USD 40 lab budget must notify at 50/75/90 percent actual spend and 100 percent forecast, to the configured email."
  }
}

run "reject_budget_above_agreed_cap" {
  command = plan

  variables {
    monthly_budget_usd = 40.01
  }

  expect_failures = [var.monthly_budget_usd]
}
