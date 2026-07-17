data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "ubuntu_2404" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  vpc_cidr           = "10.20.0.0/16"
  public_subnet_cidr = "10.20.10.0/24"
  web_private_ip     = "10.20.10.10"
  monitor_private_ip = "10.20.10.20"
  availability_zone  = data.aws_availability_zones.available.names[0]
  common_tags = {
    Project   = var.project_name
    ManagedBy = "terraform"
    Purpose   = "aws-elk-lab"
  }
}

resource "aws_vpc" "lab" {
  cidr_block           = local.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.project_name}-vpc" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.project_name}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = local.public_subnet_cidr
  availability_zone       = local.availability_zone
  map_public_ip_on_launch = false

  tags = { Name = "${var.project_name}-public-${local.availability_zone}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = { Name = "${var.project_name}-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "web" {
  name_prefix = "${var.project_name}-web-"
  description = "Web EC2: restricted HTTP and administrator SSH"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "HTTP from named lab tester CIDRs"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.tester_cidrs
  }

  ingress {
    description = "SSH from named administrator CIDRs"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  egress {
    description = "Package, image and mTLS egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.project_name}-web-sg" }
}

resource "aws_security_group" "monitor" {
  name_prefix = "${var.project_name}-monitor-"
  description = "Monitor EC2: administrator SSH and Logstash only from Web SG"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "SSH from named administrator CIDRs"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  ingress {
    description     = "Mutual-TLS Filebeat only from Web security group"
    from_port       = 5044
    to_port         = 5044
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }

  egress {
    description = "Package and image downloads"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.project_name}-monitor-sg" }
}

resource "aws_iam_role" "ec2" {
  name_prefix = "${var.project_name}-ec2-"
  description = "Minimal EC2 recovery role for Flare AWS–ELK lab"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Name = "${var.project_name}-ec2-role" }
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2" {
  name_prefix = "${var.project_name}-ec2-"
  role        = aws_iam_role.ec2.name
}

resource "aws_key_pair" "lab" {
  key_name_prefix = "${var.project_name}-"
  public_key      = var.ssh_public_key
  tags            = { Name = "${var.project_name}-admin-key" }
}

resource "aws_instance" "web" {
  ami                         = data.aws_ami.ubuntu_2404.id
  instance_type               = var.web_instance_type
  subnet_id                   = aws_subnet.public.id
  private_ip                  = local.web_private_ip
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = false
  key_name                    = aws_key_pair.lab.key_name
  iam_instance_profile        = aws_iam_instance_profile.ec2.name
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/templates/web-cloud-init.yaml.tftpl", {
    admin_cidrs  = var.admin_cidrs
    tester_cidrs = var.tester_cidrs
  })

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = var.web_root_volume_gb
    tags        = { Name = "${var.project_name}-web-root" }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  tags = { Name = "${var.project_name}-web" }
}

resource "aws_instance" "monitor" {
  ami                         = data.aws_ami.ubuntu_2404.id
  instance_type               = var.monitor_instance_type
  subnet_id                   = aws_subnet.public.id
  private_ip                  = local.monitor_private_ip
  vpc_security_group_ids      = [aws_security_group.monitor.id]
  associate_public_ip_address = false
  key_name                    = aws_key_pair.lab.key_name
  iam_instance_profile        = aws_iam_instance_profile.ec2.name
  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/templates/monitor-cloud-init.yaml.tftpl", {
    admin_cidrs            = var.admin_cidrs
    web_private_ip         = local.web_private_ip
    monitor_data_volume_id = aws_ebs_volume.monitor_data.id
  })

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = var.monitor_root_volume_gb
    tags        = { Name = "${var.project_name}-monitor-root" }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  tags = { Name = "${var.project_name}-monitor" }
}

resource "aws_ebs_volume" "monitor_data" {
  availability_zone = local.availability_zone
  size              = var.monitor_data_volume_gb
  type              = "gp3"
  encrypted         = true
  tags              = { Name = "${var.project_name}-monitor-elasticsearch-data" }
}

resource "aws_volume_attachment" "monitor_data" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.monitor_data.id
  instance_id = aws_instance.monitor.id
}

resource "aws_eip" "web" {
  domain   = "vpc"
  instance = aws_instance.web.id
  tags     = { Name = "${var.project_name}-web-eip" }
}

resource "aws_eip" "monitor" {
  domain   = "vpc"
  instance = aws_instance.monitor.id
  tags     = { Name = "${var.project_name}-monitor-eip" }
}

resource "aws_budgets_budget" "monthly" {
  name         = "${var.project_name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_email]
  }
}
