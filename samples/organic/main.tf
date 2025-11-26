# Main infrastructure - migrated from CloudFormation Q3 2023
# Contact: platform-team@company.com
# JIRA: INFRA-4521, INFRA-4892

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "company-terraform-state-prod"
    key            = "network/us-east-1/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = "us-east-1"

  assume_role {
    role_arn = "arn:aws:iam::123456789012:role/TerraformExecutionRole"
  }

  default_tags {
    tags = {
      ManagedBy   = "terraform"
      Repository  = "infra-platform"
      Environment = "production"
    }
  }
}

# Secondary region for DR - INFRA-5102
provider "aws" {
  alias  = "dr"
  region = "us-west-2"

  assume_role {
    role_arn = "arn:aws:iam::123456789012:role/TerraformExecutionRole"
  }
}

locals {
  environment = "prod"
  # TODO: Move these to variables file - INFRA-6721
  legacy_cidr = "10.50.0.0/16"  # Old datacenter range, don't change
  app_name    = "ecommerce-platform"
}

# Get current account info
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Lookup existing shared services VPC for peering
data "aws_vpc" "shared_services" {
  tags = {
    Name = "shared-services-vpc"
  }
}

# Main production VPC
# NOTE: CIDR was expanded from /20 to /16 in 2022 - see INFRA-3421
resource "aws_vpc" "main" {
  cidr_block           = "10.100.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "prod-ecommerce-vpc"
    CostCenter  = "CC-4521"
    Owner       = "platform-team"
    Environment = local.environment
  }
}

# Public subnets - note: us-east-1a has larger CIDR due to legacy ALB requirements
resource "aws_subnet" "public_1a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.100.0.0/22"  # /22 for ALB IPs - INFRA-2918
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name                     = "prod-public-1a"
    "kubernetes.io/role/elb" = "1"
    Tier                     = "public"
  }
}

resource "aws_subnet" "public_1b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.100.4.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true

  tags = {
    Name                     = "prod-public-1b"
    "kubernetes.io/role/elb" = "1"
    Tier                     = "public"
  }
}

# FIXME: This subnet is undersized, need to resize during next maintenance window
resource "aws_subnet" "public_1c" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.100.5.0/25"  # Only /25 - mistake during initial setup
  availability_zone       = "us-east-1c"
  map_public_ip_on_launch = true

  tags = {
    Name                     = "prod-public-1c"
    "kubernetes.io/role/elb" = "1"
    Tier                     = "public"
    NeedsResize              = "true"
  }
}

# Private app subnets
resource "aws_subnet" "private_app_1a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.100.10.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name                              = "prod-private-app-1a"
    "kubernetes.io/role/internal-elb" = "1"
    Tier                              = "private"
    Team                              = "backend"
  }
}

resource "aws_subnet" "private_app_1b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.100.11.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name                              = "prod-private-app-1b"
    "kubernetes.io/role/internal-elb" = "1"
    Tier                              = "private"
    Team                              = "backend"
  }
}

# Database subnet - isolated
resource "aws_subnet" "private_db_1a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.100.20.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "prod-private-db-1a"
    Tier = "database"
  }
}

resource "aws_subnet" "private_db_1b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.100.21.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "prod-private-db-1b"
    Tier = "database"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "prod-igw"
  }
}

# NAT Gateways - one per AZ for HA
resource "aws_eip" "nat_1a" {
  domain = "vpc"

  tags = {
    Name = "prod-nat-eip-1a"
  }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_eip" "nat_1b" {
  domain = "vpc"

  tags = {
    Name = "prod-nat-eip-1b"
  }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "nat_1a" {
  allocation_id = aws_eip.nat_1a.id
  subnet_id     = aws_subnet.public_1a.id

  tags = {
    Name = "prod-nat-1a"
  }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "nat_1b" {
  allocation_id = aws_eip.nat_1b.id
  subnet_id     = aws_subnet.public_1b.id

  tags = {
    Name = "prod-nat-1b"
  }

  depends_on = [aws_internet_gateway.main]
}

# VPC Flow Logs - required by security team (SEC-1892)
resource "aws_flow_log" "main" {
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60

  tags = {
    Name       = "prod-vpc-flow-logs"
    Compliance = "SOC2"
  }
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flow-logs/prod"
  retention_in_days = 90  # Compliance requirement

  tags = {
    Purpose = "vpc-flow-logs"
  }
}

resource "aws_iam_role" "flow_logs" {
  name = "vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

# VPC Endpoints for AWS services
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"

  tags = {
    Name = "prod-vpce-s3"
  }
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.us-east-1.ecr.api"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.private_app_1a.id, aws_subnet.private_app_1b.id]
  security_group_ids  = [aws_security_group.vpc_endpoints.id]

  tags = {
    Name = "prod-vpce-ecr-api"
  }
}

# Bastion host for emergency access
# TODO: Replace with SSM Session Manager - INFRA-7821
resource "aws_instance" "bastion" {
  ami                         = "ami-0fa1ca9559f1892ec"  # Amazon Linux 2023
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public_1a.id
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  key_name                    = "prod-bastion-key"
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.bastion.name

  metadata_options {
    http_tokens = "required"  # IMDSv2 required - SEC-2103
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
  }

  tags = {
    Name        = "prod-bastion"
    Owner       = "platform-team"
    Purpose     = "emergency-access"
    AutoStop    = "false"
    Environment = local.environment
  }

  lifecycle {
    ignore_changes = [ami]  # Don't replace on AMI updates
  }
}

# Legacy jump box - DO NOT DELETE - used by contractor VPN
# Ticket: INFRA-1234 - will decommission after contract ends Dec 2024
resource "aws_instance" "old_jumpbox" {
  ami                    = "ami-0abcd1234efgh5678"  # Old CentOS 7
  instance_type          = "t2.small"  # Legacy type
  subnet_id              = aws_subnet.public_1b.id
  vpc_security_group_ids = [aws_security_group.legacy_ssh.id]
  key_name               = "contractor-key-2021"

  tags = {
    Name            = "legacy-jumpbox-DONT-DELETE"
    Owner           = "john.smith"
    DecommissionDate = "2024-12-31"
    TicketRef       = "INFRA-1234"
  }
}

# API servers - mixed instance types from different scaling events
resource "aws_instance" "api_primary" {
  ami                    = "ami-0fa1ca9559f1892ec"
  instance_type          = "m5.xlarge"  # Upgraded INFRA-5521
  subnet_id              = aws_subnet.private_app_1a.id
  vpc_security_group_ids = [aws_security_group.api_servers.id]
  iam_instance_profile   = aws_iam_instance_profile.api_server.name

  tags = {
    Name        = "prod-api-1"
    Service     = "api-gateway"
    Owner       = "api-team"
    Environment = local.environment
    CostCenter  = "CC-4521"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_instance" "api_secondary" {
  ami                    = "ami-0fa1ca9559f1892ec"
  instance_type          = "m5.large"  # Smaller, added during incident
  subnet_id              = aws_subnet.private_app_1b.id
  vpc_security_group_ids = [aws_security_group.api_servers.id]
  iam_instance_profile   = aws_iam_instance_profile.api_server.name

  tags = {
    Name        = "prod-api-2"
    Service     = "api-gateway"
    Owner       = "api-team"
    Environment = local.environment
    AddedDuring = "incident-2023-11-15"  # Added during Black Friday incident
  }
}

# Worker instances - using older m4 type (grandfathered reserved instances)
resource "aws_instance" "worker_1" {
  ami                    = "ami-0abcdef1234567890"
  instance_type          = "m4.large"  # Reserved instance, expires 2025-06
  subnet_id              = aws_subnet.private_app_1a.id
  vpc_security_group_ids = [aws_security_group.workers.id]

  tags = {
    Name             = "prod-worker-batch-01"
    Service          = "batch-processor"
    ReservedInstance = "ri-0abc123"
    RIExpires        = "2025-06-30"
  }
}

# Test instance Bob left running - TODO: investigate and terminate
# resource "aws_instance" "bobs_test_instance" {
#   ami           = "ami-testing123"
#   instance_type = "t3.large"
#   subnet_id     = aws_subnet.private_app_1a.id
#   tags = {
#     Name  = "bob-test-delete-me"
#     Owner = "bob.jones"
#   }
# }
