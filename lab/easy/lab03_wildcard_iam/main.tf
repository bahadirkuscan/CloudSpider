###############################################################################
# Lab 03 — Wildcard IAM Actions (Easy)
#
# Vulnerability: iam-manager has iam:* on *, granting full IAM control
#                including credential theft and policy injection on all
#                users and roles.
#
# Scale: Medium (5 users, 3 roles, 2 groups)
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
# CloudSpider Discovery Policy
# =============================================================================

resource "aws_iam_policy" "cloudspider_discovery" {
  name = "cloudspider-discovery"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMDiscovery"
        Effect = "Allow"
        Action = ["iam:List*", "iam:Get*"]
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

  tags = { Lab = "lab03" }
}

# =============================================================================
# Platform Admin — full administrator (target)
# =============================================================================

resource "aws_iam_user" "platform_admin" {
  name = "platform-admin"
  tags = { Lab = "lab03", Role = "admin" }
}

resource "aws_iam_user_policy_attachment" "platform_admin_full" {
  user       = aws_iam_user.platform_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# =============================================================================
# IAM Manager — VULNERABLE (iam:* on *)
# =============================================================================

resource "aws_iam_user" "iam_manager" {
  name = "iam-manager"
  tags = { Lab = "lab03", Role = "iam-admin" }
}

resource "aws_iam_user_policy_attachment" "iam_manager_discovery" {
  user       = aws_iam_user.iam_manager.name
  policy_arn = aws_iam_policy.cloudspider_discovery.arn
}

resource "aws_iam_access_key" "iam_manager_key" {
  user = aws_iam_user.iam_manager.name
}

resource "aws_iam_user_policy" "iam_manager_policy" {
  name = "iam-full-access"
  user = aws_iam_user.iam_manager.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "FullIAMAccess"
        Effect   = "Allow"
        Action   = "iam:*"
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# Regular Users — benign
# =============================================================================

resource "aws_iam_user" "backend_dev" {
  name = "backend-dev"
  tags = { Lab = "lab03", Team = "engineering" }
}

resource "aws_iam_user" "frontend_dev" {
  name = "frontend-dev"
  tags = { Lab = "lab03", Team = "engineering" }
}

resource "aws_iam_user" "qa_engineer" {
  name = "qa-engineer"
  tags = { Lab = "lab03", Team = "qa" }
}

# =============================================================================
# Groups
# =============================================================================

resource "aws_iam_group" "engineering_group" {
  name = "engineering-group"
}

resource "aws_iam_group_membership" "engineering_members" {
  name  = "engineering-membership"
  group = aws_iam_group.engineering_group.name
  users = [
    aws_iam_user.backend_dev.name,
    aws_iam_user.frontend_dev.name,
  ]
}

resource "aws_iam_group_policy" "engineering_policy" {
  name  = "engineering-base"
  group = aws_iam_group.engineering_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DevToolsAccess"
        Effect = "Allow"
        Action = [
          "codecommit:*",
          "codebuild:BatchGetBuilds",
          "codebuild:StartBuild",
          "logs:GetLogEvents",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_group" "readonly_group" {
  name = "readonly-group"
}

resource "aws_iam_group_membership" "readonly_members" {
  name  = "readonly-membership"
  group = aws_iam_group.readonly_group.name
  users = [
    aws_iam_user.qa_engineer.name,
  ]
}

resource "aws_iam_group_policy_attachment" "readonly_policy" {
  group      = aws_iam_group.readonly_group.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# =============================================================================
# Roles — benign noise + escalation targets
# =============================================================================

resource "aws_iam_role" "cicd_role" {
  name = "cicd-role"

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

  tags = { Lab = "lab03" }
}

resource "aws_iam_role_policy_attachment" "cicd_deploy" {
  role       = aws_iam_role.cicd_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeDeployFullAccess"
}

resource "aws_iam_role" "monitoring_role" {
  name = "monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "monitoring.rds.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = { Lab = "lab03" }
}

resource "aws_iam_role_policy_attachment" "monitoring_cw" {
  role       = aws_iam_role.monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
}

resource "aws_iam_role" "emergency_admin_role" {
  name = "emergency-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "sts:AssumeRole"
        Condition = {
          Bool = { "aws:MultiFactorAuthPresent" = "true" }
        }
      }
    ]
  })

  tags = { Lab = "lab03", Description = "Break-glass admin" }
}

resource "aws_iam_role_policy_attachment" "emergency_admin" {
  role       = aws_iam_role.emergency_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# =============================================================================
# Outputs
# =============================================================================

output "attack_paths" {
  value = [
    "iam-manager --[CreateAccessKey]--> platform-admin",
    "iam-manager --[AdministerResource]--> platform-admin (PutUserPolicy)",
    "iam-manager --[AdministerResource]--> emergency-admin-role (UpdateAssumeRolePolicy)",
    "iam-manager --[PASS_ROLE]--> all roles",
  ]
}

output "vulnerable_principal" {
  value = aws_iam_user.iam_manager.arn
}

output "cloudspider_access_key_id" {
  value       = aws_iam_access_key.iam_manager_key.id
  description = "Access Key ID for CloudSpider"
}

output "cloudspider_secret_access_key" {
  value       = aws_iam_access_key.iam_manager_key.secret
  sensitive   = true
  description = "Secret Access Key — retrieve with: terraform output -raw cloudspider_secret_access_key"
}
