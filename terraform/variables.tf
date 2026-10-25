variable "aws_region" {
  description = "AWS region for this lab. The topology is intentionally single-AZ."
  type        = string
  default     = "ap-southeast-1"
}

variable "availability_zone" {
  description = "Preflight-selected AZ offering both instance types; null preserves automatic selection."
  type        = string
  default     = null
}

variable "ubuntu_ami_id" {
  description = "Optional pinned Canonical Ubuntu 24.04 AMI. Pin the deployed image for updates; null selects the latest matching image for a fresh lab."
  type        = string
  default     = null

  validation {
    condition     = var.ubuntu_ami_id == null || can(regex("^ami-[0-9a-f]{8,17}$", var.ubuntu_ami_id))
    error_message = "ubuntu_ami_id must be null or a valid EC2 AMI ID."
  }
}

variable "project_name" {
  description = "Prefix for AWS resources and tags."
  type        = string
  default     = "flare-aws-elk-lab"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,40}$", var.project_name))
    error_message = "project_name must be 3-41 lowercase letters, digits or hyphens and start with a letter."
  }
}

variable "admin_cidrs" {
  description = "One or more administrator IPv4 CIDRs allowed to use SSH. Never use 0.0.0.0/0."
  type        = list(string)

  validation {
    condition     = length(var.admin_cidrs) > 0 && alltrue([for cidr in var.admin_cidrs : can(cidrnetmask(cidr)) && cidr != "0.0.0.0/0"])
    error_message = "admin_cidrs must be valid CIDRs and must not include 0.0.0.0/0."
  }
}

variable "tester_cidrs" {
  description = "One or more tester IPv4 CIDRs allowed to reach lab HTTP port 80. Never use 0.0.0.0/0."
  type        = list(string)

  validation {
    condition     = length(var.tester_cidrs) > 0 && alltrue([for cidr in var.tester_cidrs : can(cidrnetmask(cidr)) && cidr != "0.0.0.0/0"])
    error_message = "tester_cidrs must be valid CIDRs and must not include 0.0.0.0/0."
  }
}

variable "ssh_public_key" {
  description = "OpenSSH public key material only. Do not pass a private key to Terraform."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^(ssh-(ed25519|rsa|ecdsa) |sk-ssh-ed25519@openssh.com )", var.ssh_public_key)) && !can(regex("BEGIN (OPENSSH|RSA|EC|PRIVATE) KEY", var.ssh_public_key))
    error_message = "ssh_public_key must be one OpenSSH public key and must never contain private-key material."
  }
}

variable "web_instance_type" {
  description = "Instance type for Nginx, Spring Boot, MySQL, Redis and Filebeat."
  type        = string
  default     = "m7i-flex.large"
}

variable "monitor_instance_type" {
  description = "Instance type for Elasticsearch, Logstash and Kibana."
  type        = string
  default     = "m7i-flex.large"
}

variable "web_root_volume_gb" {
  description = "Encrypted gp3 root volume size for the Web EC2."
  type        = number
  default     = 40

  validation {
    condition     = var.web_root_volume_gb >= 40
    error_message = "web_root_volume_gb must be at least 40 GB."
  }
}

variable "monitor_root_volume_gb" {
  description = "Encrypted gp3 root volume size for the Monitor EC2."
  type        = number
  default     = 20

  validation {
    condition     = var.monitor_root_volume_gb >= 20
    error_message = "monitor_root_volume_gb must be at least 20 GB."
  }
}

variable "monitor_data_volume_gb" {
  description = "Encrypted gp3 data volume size for Elasticsearch data."
  type        = number
  default     = 80

  validation {
    condition     = var.monitor_data_volume_gb >= 80
    error_message = "monitor_data_volume_gb must be at least 80 GB."
  }
}

variable "budget_email" {
  description = "Email recipient for AWS Budget notifications. No credentials are stored in Terraform."
  type        = string

  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.budget_email))
    error_message = "budget_email must be a valid email address."
  }
}

variable "monthly_budget_usd" {
  description = "Monthly AWS cost alert threshold in USD."
  type        = number
  default     = 40

  validation {
    condition     = var.monthly_budget_usd > 0 && var.monthly_budget_usd <= 40
    error_message = "monthly_budget_usd must be positive and must not exceed the agreed USD 40 account budget."
  }
}
