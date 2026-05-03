###############################################################################
# Lab 01 — Overprivileged User (Easy)
# 
# Vulnerability: dev-user has iam:CreateAccessKey on all users, enabling
#                credential theft of the admin-user account.
#
# Scale: Small (2 users, 1 role)
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

data "aws_caller_identity" "current" {}

# =============================================================================
# CloudSpider Discovery Policy — read-only access for environment enumeration
# =============================================================================

resource "aws_iam_policy" "cloudspider_discovery" {
  name = "cloudspider-discovery"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMDiscovery"
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListRoles",
          "iam:ListGroups",
          "iam:ListGroupsForUser",
          "iam:ListUserPolicies",
          "iam:ListAttachedUserPolicies",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListGroupPolicies",
          "iam:ListAttachedGroupPolicies",
          "iam:GetUserPolicy",
          "iam:GetRolePolicy",
          "iam:GetGroupPolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetUser",
          "iam:GetRole",
          "iam:GetGroup"
        ]
        Resource = "*"
      },
      {
        Sid    = "ResourceDiscovery"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "ec2:DescribeInstances",
          "lambda:ListFunctions",
          "lambda:GetFunction",
          "rds:DescribeDBInstances",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      }
    ]
  })

  tags = { Lab = "lab01" }
}

# =============================================================================
# Admin User — full AdministratorAccess
# =============================================================================

resource "aws_iam_user" "admin_user" {
  name = "admin-user"

  tags = {
    Lab         = "lab01"
    Description = "Full administrator"
  }
}

resource "aws_iam_user_policy_attachment" "admin_full" {
  user       = aws_iam_user.admin_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# =============================================================================
# Dev User — has iam:CreateAccessKey on all users (VULNERABLE)
# =============================================================================

resource "aws_iam_user" "dev_user" {
  name = "dev-user"

  tags = {
    Lab         = "lab01"
    Description = "Developer with overly broad IAM key creation"
  }
}

resource "aws_iam_user_policy_attachment" "dev_discovery" {
  user       = aws_iam_user.dev_user.name
  policy_arn = aws_iam_policy.cloudspider_discovery.arn
}

resource "aws_iam_access_key" "dev_user_key" {
  user = aws_iam_user.dev_user.name
}

# Legitimate development permissions
resource "aws_iam_user_policy" "dev_base" {
  name = "dev-base-policy"
  user = aws_iam_user.dev_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowCodeCommit"
        Effect   = "Allow"
        Action   = [
          "codecommit:GitPull",
          "codecommit:GitPush",
          "codecommit:ListRepositories"
        ]
        Resource = "*"
      },
      {
        Sid      = "AllowCloudWatchLogs"
        Effect   = "Allow"
        Action   = [
          "logs:GetLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# VULNERABILITY: CreateAccessKey on all users
resource "aws_iam_user_policy" "dev_key_management" {
  name = "dev-key-rotation-policy"
  user = aws_iam_user.dev_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowKeyRotation"
        Effect   = "Allow"
        Action   = "iam:CreateAccessKey"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"
      }
    ]
  })
}

# =============================================================================
# Deploy Role — benign noise
# =============================================================================

resource "aws_iam_role" "deploy_role" {
  name = "deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "codebuild.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Lab         = "lab01"
    Description = "CI/CD deployment role - benign"
  }
}

resource "aws_iam_role_policy_attachment" "deploy_s3" {
  role       = aws_iam_role.deploy_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# =============================================================================
# Outputs
# =============================================================================

output "attack_path" {
  value = "dev-user --[CreateAccessKey]--> admin-user"
}

output "vulnerable_principal" {
  value = aws_iam_user.dev_user.arn
}

output "target_principal" {
  value = aws_iam_user.admin_user.arn
}

output "cloudspider_access_key_id" {
  value       = aws_iam_access_key.dev_user_key.id
  description = "Access Key ID for CloudSpider — configure in the GUI Credential Manager"
}

output "cloudspider_secret_access_key" {
  value       = aws_iam_access_key.dev_user_key.secret
  sensitive   = true
  description = "Secret Access Key — retrieve with: terraform output -raw cloudspider_secret_access_key"
}
