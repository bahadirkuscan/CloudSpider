###############################################################################
# Lab 06 — EC2 Instance Profile Pivot (Medium)
#
# Vulnerability: devops-user can ec2:RunInstances + iam:PassRole to
#                ec2-admin-role, enabling launch of an EC2 instance with
#                admin credentials accessible via IMDS.
#
# Scale: Medium (4 users, 4 roles, 3 EC2 instances, 1 Lambda)
###############################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "AWS region to deploy lab resources"
  type        = string
  default     = "us-east-1"
}

variable "ami_id" {
  description = "AMI ID for EC2 instances (Amazon Linux 2)"
  type        = string
  default     = "ami-0c02fb55956c7d316" # Amazon Linux 2 us-east-1
}

data "aws_caller_identity" "current" {}

# =============================================================================
# CloudSpider Discovery Policy
# =============================================================================

resource "aws_iam_policy" "cloudspider_discovery" {
  name = "cloudspider-discovery"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "IAMDiscovery"
        Effect   = "Allow"
        Action   = ["iam:List*", "iam:Get*"]
        Resource = "*"
      },
      {
        Sid    = "ResourceDiscovery"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets", "ec2:DescribeInstances",
          "lambda:ListFunctions", "lambda:GetFunction",
          "rds:DescribeDBInstances", "sts:GetCallerIdentity"
        ]
        Resource = "*"
      }
    ]
  })

  tags = { Lab = "lab06" }
}

# =============================================================================
# IAM Roles
# =============================================================================

# TARGET: EC2 admin role
resource "aws_iam_role" "ec2_admin_role" {
  name = "ec2-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = { Lab = "lab06", Description = "EC2 admin role - target" }
}

resource "aws_iam_role_policy_attachment" "ec2_admin_full" {
  role       = aws_iam_role.ec2_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "ec2_admin_profile" {
  name = "ec2-admin-profile"
  role = aws_iam_role.ec2_admin_role.name
}

# Benign: app-level EC2 role
resource "aws_iam_role" "ec2_app_role" {
  name = "ec2-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = { Lab = "lab06" }
}

resource "aws_iam_role_policy_attachment" "ec2_app_s3" {
  role       = aws_iam_role.ec2_app_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_instance_profile" "ec2_app_profile" {
  name = "ec2-app-profile"
  role = aws_iam_role.ec2_app_role.name
}

# Benign: monitoring EC2 role
resource "aws_iam_role" "ec2_monitoring_role" {
  name = "ec2-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = { Lab = "lab06" }
}

resource "aws_iam_role_policy_attachment" "ec2_monitoring_cw" {
  role       = aws_iam_role.ec2_monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "ec2_monitoring_profile" {
  name = "ec2-monitoring-profile"
  role = aws_iam_role.ec2_monitoring_role.name
}

# Benign: Lambda ETL role
resource "aws_iam_role" "lambda_etl_role" {
  name = "lambda-etl-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = { Lab = "lab06" }
}

resource "aws_iam_role_policy_attachment" "lambda_etl_s3" {
  role       = aws_iam_role.lambda_etl_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# =============================================================================
# EC2 Instances (benign noise)
# =============================================================================

resource "aws_instance" "web_server_1" {
  ami                  = var.ami_id
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.ec2_app_profile.name

  tags = {
    Name = "web-server-1"
    Lab  = "lab06"
  }
}

resource "aws_instance" "batch_worker_1" {
  ami                  = var.ami_id
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.ec2_monitoring_profile.name

  tags = {
    Name = "batch-worker-1"
    Lab  = "lab06"
  }
}

resource "aws_instance" "bastion_host" {
  ami           = var.ami_id
  instance_type = "t3.micro"

  tags = {
    Name = "bastion-host"
    Lab  = "lab06"
  }
}

# =============================================================================
# Lambda Function (benign noise)
# =============================================================================

data "archive_file" "dummy_lambda" {
  type        = "zip"
  output_path = "${path.module}/lambda_placeholder.zip"

  source {
    content  = "def handler(event, context): return {'statusCode': 200}"
    filename = "index.py"
  }
}

resource "aws_lambda_function" "etl_processor" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "etl-processor"
  role             = aws_iam_role.lambda_etl_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256

  tags = { Lab = "lab06" }
}

# =============================================================================
# Users
# =============================================================================

# VULNERABLE: devops-user with RunInstances + PassRole
resource "aws_iam_user" "devops_user" {
  name = "devops-user"
  tags = { Lab = "lab06", Team = "devops" }
}

resource "aws_iam_user_policy_attachment" "devops_discovery" {
  user       = aws_iam_user.devops_user.name
  policy_arn = aws_iam_policy.cloudspider_discovery.arn
}

resource "aws_iam_access_key" "devops_user_key" {
  user = aws_iam_user.devops_user.name
}

resource "aws_iam_user_policy" "devops_ec2" {
  name = "devops-ec2-management"
  user = aws_iam_user.devops_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Management"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:DescribeInstances",
          "ec2:TerminateInstances",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
          "ec2:DescribeImages",
          "ec2:DescribeKeyPairs"
        ]
        Resource = "*"
      }
    ]
  })
}

# VULNERABILITY: PassRole to any ec2-* role (includes ec2-admin-role)
resource "aws_iam_user_policy" "devops_passrole" {
  name = "devops-passrole"
  user = aws_iam_user.devops_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PassRoleForEC2"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/ec2-*"
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ec2.amazonaws.com"
          }
        }
      }
    ]
  })
}

# Benign users
resource "aws_iam_user" "app_developer" {
  name = "app-developer"
  tags = { Lab = "lab06", Team = "engineering" }
}

resource "aws_iam_user_policy_attachment" "app_dev_codecommit" {
  user       = aws_iam_user.app_developer.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeCommitPowerUser"
}

resource "aws_iam_user" "db_admin" {
  name = "db-admin"
  tags = { Lab = "lab06", Team = "data" }
}

resource "aws_iam_user_policy_attachment" "db_admin_rds" {
  user       = aws_iam_user.db_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSFullAccess"
}

resource "aws_iam_user" "network_engineer" {
  name = "network-engineer"
  tags = { Lab = "lab06", Team = "network" }
}

resource "aws_iam_user_policy_attachment" "network_vpc" {
  user       = aws_iam_user.network_engineer.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonVPCFullAccess"
}

# =============================================================================
# Outputs
# =============================================================================

output "attack_path" {
  value = "devops-user --[CanRunInstance + PASS_ROLE]--> ec2-admin-role (via new EC2 instance)"
}

output "vulnerable_principal" {
  value = aws_iam_user.devops_user.arn
}

output "target_role" {
  value = aws_iam_role.ec2_admin_role.arn
}

output "cloudspider_access_key_id" {
  value       = aws_iam_access_key.devops_user_key.id
  description = "Access Key ID for CloudSpider"
}

output "cloudspider_secret_access_key" {
  value       = aws_iam_access_key.devops_user_key.secret
  sensitive   = true
  description = "Secret Access Key — retrieve with: terraform output -raw cloudspider_secret_access_key"
}
