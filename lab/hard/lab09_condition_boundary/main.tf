###############################################################################
# Lab 09 — Condition & Boundary Evasion (Hard)
#
# Vulnerability: Multiple layered defense mechanisms, each with a subtle flaw:
#   1. Permissions Boundary allows sts:AssumeRole → boundary escape
#   2. Region condition doesn't apply to global IAM calls
#   3. Trust policy with Principal=* gated by PrincipalAccount (trivially met)
#
# Scale: Large (10 users, 8 roles, 3 groups, 2 EC2, 1 Lambda, 2 S3)
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
  description = "AMI ID for EC2 instances"
  type        = string
  default     = "ami-0c02fb55956c7d316"
}

variable "org_id" {
  description = "AWS Organization ID (for condition simulation)"
  type        = string
  default     = "o-exampleorgid"
}

data "aws_caller_identity" "current" {}
locals {
  account_id = data.aws_caller_identity.current.account_id
}

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

  tags = { Lab = "lab09" }
}

# =============================================================================
# S3 Buckets
# =============================================================================

resource "aws_s3_bucket" "app_data" {
  bucket = "app-data-${local.account_id}"
  tags   = { Lab = "lab09" }
}

resource "aws_s3_bucket" "app_logs" {
  bucket = "app-logs-${local.account_id}"
  tags   = { Lab = "lab09" }
}

# =============================================================================
# Permissions Boundary Policy
# =============================================================================

resource "aws_iam_policy" "dev_boundary" {
  name = "dev-permissions-boundary"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowedServices"
        Effect = "Allow"
        Action = [
          "s3:*",
          "ec2:Describe*",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "lambda:GetFunction",
          "lambda:ListFunctions",
          "lambda:InvokeFunction",
          "logs:*",
          "cloudwatch:GetMetricData",
          "cloudwatch:ListMetrics",
          "sts:AssumeRole",
          "sts:GetCallerIdentity",
          "iam:List*",
          "iam:Get*",
          "rds:DescribeDBInstances"
        ]
        Resource = "*"
      },
      {
        Sid      = "DenyIAMEscalation"
        Effect   = "Deny"
        Action   = [
          "iam:CreateUser",
          "iam:CreateRole",
          "iam:PutUserPolicy",
          "iam:AttachUserPolicy",
          "iam:PutRolePolicy",
          "iam:AttachRolePolicy",
          "iam:CreateAccessKey",
          "iam:UpdateAssumeRolePolicy"
        ]
        Resource = "*"
      }
    ]
  })

  tags = { Lab = "lab09", Description = "Permissions boundary for devs" }
}

# =============================================================================
# ESCALATION CHAIN ROLES
# =============================================================================

# Hop 1 target: infra-deploy-role (NO permissions boundary!)
resource "aws_iam_role" "infra_deploy_role" {
  name = "infra-deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab09", Description = "Infrastructure deployment - NO boundary" }
}

# Flaw 2: Region condition that doesn't apply to IAM (global service)
resource "aws_iam_role_policy" "infra_deploy_policy" {
  name = "infra-deploy-access"
  role = aws_iam_role.infra_deploy_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RegionRestrictedAccess"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = [var.region, "us-west-2"]
          }
        }
      },
      {
        Sid    = "AllowGlobalServices"
        Effect = "Allow"
        Action = [
          "iam:List*",
          "iam:Get*",
          "sts:AssumeRole",
          "sts:GetCallerIdentity",
          "organizations:Describe*",
          "organizations:List*"
        ]
        Resource = "*"
      }
    ]
  })
}

# Hop 2 target: super-admin-role (final target)
# Flaw 3: Trust policy with Principal=* and org condition
resource "aws_iam_role" "super_admin_role" {
  name = "super-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:PrincipalAccount" = local.account_id
        }
      }
    }]
  })

  tags = { Lab = "lab09", Description = "Super admin - FINAL TARGET" }
}

resource "aws_iam_role_policy_attachment" "super_admin_full" {
  role       = aws_iam_role.super_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# =============================================================================
# NOISE ROLES (legitimate, properly secured)
# =============================================================================

resource "aws_iam_role" "app_ec2_role" {
  name = "app-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab09" }
}

resource "aws_iam_role_policy_attachment" "app_ec2_s3" {
  role       = aws_iam_role.app_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_instance_profile" "app_ec2_profile" {
  name = "app-ec2-profile"
  role = aws_iam_role.app_ec2_role.name
}

resource "aws_iam_role" "lambda_processor_role" {
  name = "lambda-processor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab09" }
}

resource "aws_iam_role_policy_attachment" "lambda_proc_exec" {
  role       = aws_iam_role.lambda_processor_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "cloudtrail_role" {
  name = "cloudtrail-delivery-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab09" }
}

resource "aws_iam_role" "ssm_maintenance_role" {
  name = "ssm-maintenance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ssm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab09" }
}

resource "aws_iam_role" "cost_optimizer_role" {
  name = "cost-optimizer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cost-optimization-hub.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab09" }
}

# =============================================================================
# EC2 Instances
# =============================================================================

resource "aws_instance" "app_server_1" {
  ami                  = var.ami_id
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.app_ec2_profile.name

  tags = { Name = "app-server-1", Lab = "lab09" }
}

resource "aws_instance" "app_server_2" {
  ami                  = var.ami_id
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.app_ec2_profile.name

  tags = { Name = "app-server-2", Lab = "lab09" }
}

# =============================================================================
# Lambda Function
# =============================================================================

data "archive_file" "dummy_lambda" {
  type        = "zip"
  output_path = "${path.module}/lambda_placeholder.zip"

  source {
    content  = "def handler(event, context): return {'statusCode': 200}"
    filename = "index.py"
  }
}

resource "aws_lambda_function" "data_processor" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "data-processor-v2"
  role             = aws_iam_role.lambda_processor_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256

  tags = { Lab = "lab09" }
}

# =============================================================================
# Groups
# =============================================================================

resource "aws_iam_group" "dev_team" {
  name = "dev-team"
}

resource "aws_iam_group_policy" "dev_team_base" {
  name  = "dev-base-access"
  group = aws_iam_group.dev_team.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DevTools"
      Effect = "Allow"
      Action = [
        "codecommit:*",
        "codebuild:BatchGetBuilds",
        "codebuild:StartBuild",
        "logs:GetLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_group" "ops_team" {
  name = "ops-team"
}

resource "aws_iam_group_policy" "ops_team_base" {
  name  = "ops-base-access"
  group = aws_iam_group.ops_team.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "OpsMonitoring"
      Effect = "Allow"
      Action = [
        "cloudwatch:*",
        "logs:*",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ssm:DescribeInstanceInformation"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_group" "security_team" {
  name = "security-team"
}

resource "aws_iam_group_policy_attachment" "security_audit" {
  group      = aws_iam_group.security_team.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# =============================================================================
# Users
# =============================================================================

# VULNERABLE: restricted-dev with permissions boundary (Flaw 1)
resource "aws_iam_user" "restricted_dev" {
  name                 = "restricted-dev"
  permissions_boundary = aws_iam_policy.dev_boundary.arn
  tags                 = { Lab = "lab09", Team = "dev" }
}

resource "aws_iam_user_policy_attachment" "restricted_dev_discovery" {
  user       = aws_iam_user.restricted_dev.name
  policy_arn = aws_iam_policy.cloudspider_discovery.arn
}

resource "aws_iam_access_key" "restricted_dev_key" {
  user = aws_iam_user.restricted_dev.name
}

# Inline policy granting sts:AssumeRole (allowed by boundary)
resource "aws_iam_user_policy" "restricted_dev_policy" {
  name = "restricted-dev-access"
  user = aws_iam_user.restricted_dev.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DevAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "ec2:Describe*",
          "logs:*"
        ]
        Resource = "*"
      },
      {
        Sid      = "AssumeDeployRole"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::${local.account_id}:role/infra-deploy-role"
      }
    ]
  })
}

# Other devs with same boundary (don't have AssumeRole in inline policy)
resource "aws_iam_user" "dev_1" {
  name                 = "developer-1"
  permissions_boundary = aws_iam_policy.dev_boundary.arn
  tags                 = { Lab = "lab09", Team = "dev" }
}

resource "aws_iam_user" "dev_2" {
  name                 = "developer-2"
  permissions_boundary = aws_iam_policy.dev_boundary.arn
  tags                 = { Lab = "lab09", Team = "dev" }
}

resource "aws_iam_user" "dev_3" {
  name                 = "developer-3"
  permissions_boundary = aws_iam_policy.dev_boundary.arn
  tags                 = { Lab = "lab09", Team = "dev" }
}

resource "aws_iam_group_membership" "dev_members" {
  name  = "dev-membership"
  group = aws_iam_group.dev_team.name
  users = [
    aws_iam_user.restricted_dev.name,
    aws_iam_user.dev_1.name,
    aws_iam_user.dev_2.name,
    aws_iam_user.dev_3.name,
  ]
}

# Ops team
resource "aws_iam_user" "ops_lead" {
  name = "ops-lead"
  tags = { Lab = "lab09", Team = "ops" }
}

resource "aws_iam_user" "ops_oncall" {
  name = "ops-oncall"
  tags = { Lab = "lab09", Team = "ops" }
}

resource "aws_iam_group_membership" "ops_members" {
  name  = "ops-membership"
  group = aws_iam_group.ops_team.name
  users = [
    aws_iam_user.ops_lead.name,
    aws_iam_user.ops_oncall.name,
  ]
}

# Security team
resource "aws_iam_user" "sec_analyst" {
  name = "security-analyst"
  tags = { Lab = "lab09", Team = "security" }
}

resource "aws_iam_group_membership" "security_members" {
  name  = "security-membership"
  group = aws_iam_group.security_team.name
  users = [
    aws_iam_user.sec_analyst.name,
  ]
}

# Admin users
resource "aws_iam_user" "super_admin_user" {
  name = "super-admin-user"
  tags = { Lab = "lab09", Team = "admin" }
}

resource "aws_iam_user_policy_attachment" "super_admin_user_full" {
  user       = aws_iam_user.super_admin_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "billing_user" {
  name = "billing-user"
  tags = { Lab = "lab09", Team = "finance" }
}

resource "aws_iam_user_policy_attachment" "billing_user_policy" {
  user       = aws_iam_user.billing_user.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/Billing"
}

# =============================================================================
# Outputs
# =============================================================================

output "attack_chain" {
  value = [
    "Flaw 1: restricted-dev (boundary allows sts:AssumeRole) --[ASSUME_ROLE]--> infra-deploy-role (NO boundary)",
    "Flaw 2: infra-deploy-role has iam:*/sts:* — region condition doesn't apply to global IAM",
    "Flaw 3: infra-deploy-role --[ASSUME_ROLE]--> super-admin-role (Principal=*, AccountID condition trivially met)",
  ]
}

output "defense_layers" {
  value = [
    "Layer 1: Permissions Boundary on restricted-dev (blocks iam:*, allows sts:AssumeRole)",
    "Layer 2: Region condition on infra-deploy-role (ineffective for IAM global calls)",
    "Layer 3: PrincipalAccount condition on super-admin-role trust (met by all in-account principals)",
  ]
}

output "chain_entry_point" {
  value = aws_iam_user.restricted_dev.arn
}

output "chain_final_target" {
  value = aws_iam_role.super_admin_role.arn
}

output "cloudspider_access_key_id" {
  value       = aws_iam_access_key.restricted_dev_key.id
  description = "Access Key ID for CloudSpider"
}

output "cloudspider_secret_access_key" {
  value       = aws_iam_access_key.restricted_dev_key.secret
  sensitive   = true
  description = "Secret Access Key — retrieve with: terraform output -raw cloudspider_secret_access_key"
}
