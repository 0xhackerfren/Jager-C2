terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

# Variables
variable "region" {
  type    = string
  default = "us-east-1"
}

variable "engagement_id" {
  type        = string
  description = "Unique engagement identifier"
}

variable "operator_ips" {
  type        = list(string)
  description = "Operator IPs allowed to access teamserver"
}

variable "domain" {
  type        = string
  description = "C2 domain name"
}

variable "redirector_count" {
  type    = number
  default = 2
}

provider "aws" {
  region = var.region
}

# Random suffix for unique naming
resource "random_id" "suffix" {
  byte_length = 4
}

# VPC for C2 infrastructure
resource "aws_vpc" "c2" {
  cidr_block           = "10.200.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name       = "jager-${var.engagement_id}"
    Engagement = var.engagement_id
  }
}

resource "aws_subnet" "c2_public" {
  vpc_id                  = aws_vpc.c2.id
  cidr_block              = "10.200.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "jager-public-${random_id.suffix.hex}"
  }
}

resource "aws_subnet" "c2_private" {
  vpc_id     = aws_vpc.c2.id
  cidr_block = "10.200.2.0/24"

  tags = {
    Name = "jager-private-${random_id.suffix.hex}"
  }
}

resource "aws_internet_gateway" "c2" {
  vpc_id = aws_vpc.c2.id
}

resource "aws_route_table" "c2_public" {
  vpc_id = aws_vpc.c2.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.c2.id
  }
}

resource "aws_route_table_association" "c2_public" {
  subnet_id      = aws_subnet.c2_public.id
  route_table_id = aws_route_table.c2_public.id
}

# Security Groups
resource "aws_security_group" "teamserver" {
  name   = "jager-teamserver-${random_id.suffix.hex}"
  vpc_id = aws_vpc.c2.id

  # gRPC from operators
  ingress {
    from_port   = 50051
    to_port     = 50051
    protocol    = "tcp"
    cidr_blocks = var.operator_ips
  }

  # From redirectors
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.redirector.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "redirector" {
  name   = "jager-redirector-${random_id.suffix.hex}"
  vpc_id = aws_vpc.c2.id

  # HTTPS from anywhere (implant callbacks)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP for Let's Encrypt
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # DNS
  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Teamserver EC2
resource "aws_instance" "teamserver" {
  ami                    = "ami-0c7217cdde317cfec" # Ubuntu 22.04
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.c2_private.id
  vpc_security_group_ids = [aws_security_group.teamserver.id]

  root_block_device {
    volume_size = 50
    encrypted   = true
  }

  tags = {
    Name       = "jager-teamserver-${random_id.suffix.hex}"
    Engagement = var.engagement_id
    Role       = "teamserver"
  }
}

# Redirectors
resource "aws_instance" "redirector" {
  count                  = var.redirector_count
  ami                    = "ami-0c7217cdde317cfec"
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.c2_public.id
  vpc_security_group_ids = [aws_security_group.redirector.id]

  root_block_device {
    volume_size = 20
    encrypted   = true
  }

  tags = {
    Name       = "jager-redir-${count.index}-${random_id.suffix.hex}"
    Engagement = var.engagement_id
    Role       = "redirector"
  }
}

# Outputs
output "teamserver_private_ip" {
  value = aws_instance.teamserver.private_ip
}

output "redirector_public_ips" {
  value = aws_instance.redirector[*].public_ip
}

output "vpc_id" {
  value = aws_vpc.c2.id
}
