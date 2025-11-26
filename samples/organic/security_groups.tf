# Security Groups
# Last audit: 2024-01-15 (SEC-3421)

# Bastion SG - restricted to office IPs
resource "aws_security_group" "bastion" {
  name        = "prod-bastion-sg"
  description = "Bastion host security group - office IPs only"
  vpc_id      = aws_vpc.main.id

  # Office VPN
  ingress {
    description = "SSH from HQ office"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]  # HQ office
  }

  # Remote office added during COVID - INFRA-4102
  ingress {
    description = "SSH from remote office"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["198.51.100.0/24"]
  }

  # Temporary rule for security audit - remove after 2024-02-28
  # Ticket: SEC-4521
  ingress {
    description = "Temp: Security audit firm"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["192.0.2.50/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name       = "prod-bastion-sg"
    LastAudit  = "2024-01-15"
    ManagedBy  = "terraform"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Legacy SSH - for contractor jumpbox
# FIXME: Too permissive, but contractor needs it - lock down after contract ends
resource "aws_security_group" "legacy_ssh" {
  name        = "legacy-contractor-ssh"
  description = "Legacy SSH access for contractor - TEMPORARY"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from contractor VPN"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.200.0.0/16"]  # Contractor VPN range
  }

  # Added because contractor couldn't connect - INFRA-6102
  ingress {
    description = "SSH from contractor home - John D"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["73.45.123.89/32"]  # John's home IP
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "legacy-contractor-ssh"
    TEMPORARY   = "true"
    RemoveAfter = "2024-12-31"
    Ticket      = "INFRA-1234"
  }
}

# API servers SG - accumulated rules over time
resource "aws_security_group" "api_servers" {
  name        = "prod-api-servers"
  description = "API server security group"
  vpc_id      = aws_vpc.main.id

  # Main API traffic from ALB
  ingress {
    description     = "HTTPS from ALB"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Legacy HTTP endpoint - TODO: migrate to HTTPS (INFRA-8821)
  ingress {
    description     = "HTTP from ALB (legacy)"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Health check endpoint
  ingress {
    description     = "Health check"
    from_port       = 8081
    to_port         = 8081
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Internal service mesh - added for Consul
  ingress {
    description = "Consul gossip"
    from_port   = 8301
    to_port     = 8301
    protocol    = "tcp"
    self        = true
  }

  ingress {
    description = "Consul gossip UDP"
    from_port   = 8301
    to_port     = 8301
    protocol    = "udp"
    self        = true
  }

  # Prometheus scraping - monitoring team request
  ingress {
    description = "Prometheus metrics"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = ["10.100.30.0/24"]  # Monitoring subnet
  }

  # Debug port - REMOVE IN PROD (keeping for now per INFRA-7621)
  # ingress {
  #   description = "Debug port - DEV ONLY"
  #   from_port   = 9999
  #   to_port     = 9999
  #   protocol    = "tcp"
  #   cidr_blocks = ["10.100.0.0/16"]
  # }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name      = "prod-api-servers-sg"
    Service   = "api"
    ManagedBy = "terraform"
  }
}

# ALB security group
resource "aws_security_group" "alb" {
  name        = "prod-alb"
  description = "Application Load Balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP redirect
  ingress {
    description = "HTTP redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "prod-alb-sg"
  }
}

# Workers SG
resource "aws_security_group" "workers" {
  name        = "prod-workers"
  description = "Batch worker instances"
  vpc_id      = aws_vpc.main.id

  # SQS polling doesn't need ingress, but added for debugging
  ingress {
    description     = "SSH from bastion"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "prod-workers-sg"
    Service = "batch"
  }
}

# VPC Endpoints SG
resource "aws_security_group" "vpc_endpoints" {
  name        = "prod-vpc-endpoints"
  description = "VPC endpoint interfaces"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "prod-vpce-sg"
  }
}

# Database SG - very restricted
resource "aws_security_group" "database" {
  name        = "prod-database"
  description = "RDS database access"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from API servers"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.api_servers.id]
  }

  ingress {
    description     = "PostgreSQL from workers"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.workers.id]
  }

  # Temporary access for DB migration - INFRA-9102
  # Added: 2024-01-20, Remove: 2024-02-15
  ingress {
    description     = "Temp: DB migration tool"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  tags = {
    Name      = "prod-database-sg"
    Sensitive = "true"
  }
}
