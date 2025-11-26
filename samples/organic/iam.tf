# IAM Roles and Policies
# Owner: platform-team
# Last review: Q4 2023 (SEC-2891)

# Bastion instance profile
resource "aws_iam_instance_profile" "bastion" {
  name = "prod-bastion-profile"
  role = aws_iam_role.bastion.name
}

resource "aws_iam_role" "bastion" {
  name = "prod-bastion-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = {
    Purpose = "bastion-host"
  }
}

# SSM for bastion - allows Session Manager access
resource "aws_iam_role_policy_attachment" "bastion_ssm" {
  role       = aws_iam_role.bastion.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# API Server role
resource "aws_iam_instance_profile" "api_server" {
  name = "prod-api-server-profile"
  role = aws_iam_role.api_server.name
}

resource "aws_iam_role" "api_server" {
  name = "prod-api-server-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = {
    Service = "api"
  }
}

# API server needs S3, SQS, and Secrets Manager
resource "aws_iam_role_policy" "api_server" {
  name = "prod-api-server-policy"
  role = aws_iam_role.api_server.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3Access"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::company-prod-assets",
          "arn:aws:s3:::company-prod-assets/*",
          "arn:aws:s3:::company-prod-uploads",
          "arn:aws:s3:::company-prod-uploads/*"
        ]
      },
      {
        Sid    = "SQSAccess"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = "arn:aws:sqs:us-east-1:${data.aws_caller_identity.current.account_id}:prod-*"
      },
      {
        Sid    = "SecretsAccess"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "arn:aws:secretsmanager:us-east-1:${data.aws_caller_identity.current.account_id}:prod/*"
      },
      # TODO: Tighten this down - added during incident INFRA-7821
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "api_server_ssm" {
  role       = aws_iam_role.api_server.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
