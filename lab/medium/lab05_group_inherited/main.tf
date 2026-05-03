###############################################################################
# Lab 05 — Group Inherited Escalation (Medium)
#
# Vulnerability: readonly-support-group has an inline policy that grants
#                sts:AssumeRole to ops-admin-role. All group members
#                (including the intern) inherit this privilege.
#
# Scale: Medium (8 users, 3 groups, 4 roles)
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

  tags = { Lab = "lab05" }
}

# =============================================================================
# Roles
# =============================================================================

# TARGET: Operations admin role
resource "aws_iam_role" "ops_admin_role" {
  name = "ops-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = { Lab = "lab05", Description = "Ops admin role - target" }
}

resource "aws_iam_role_policy_attachment" "ops_admin_full" {
  role       = aws_iam_role.ops_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Benign roles
resource "aws_iam_role" "cloudwatch_role" {
  name = "cloudwatch-monitoring-role"

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

  tags = { Lab = "lab05" }
}

resource "aws_iam_role_policy_attachment" "cloudwatch_ro" {
  role       = aws_iam_role.cloudwatch_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
}

resource "aws_iam_role" "config_role" {
  name = "config-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = { Lab = "lab05" }
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/Config-role"
}

resource "aws_iam_role" "backup_role" {
  name = "backup-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "backup.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = { Lab = "lab05" }
}

resource "aws_iam_role_policy_attachment" "backup_policy" {
  role       = aws_iam_role.backup_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

# =============================================================================
# Groups
# =============================================================================

# VULNERABLE GROUP: has hidden AssumeRole to ops-admin-role
resource "aws_iam_group" "readonly_support_group" {
  name = "readonly-support-group"
}

resource "aws_iam_group_policy" "support_group_policy" {
  name  = "support-access"
  group = aws_iam_group.readonly_support_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SupportReadOnly"
        Effect = "Allow"
        Action = [
          "support:*",
          "trustedadvisor:*",
          "health:Describe*",
          "health:List*"
        ]
        Resource = "*"
      },
      {
        Sid      = "AssumeOpsRole"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.ops_admin_role.arn
      }
    ]
  })
}

# SRE Group — benign
resource "aws_iam_group" "sre_group" {
  name = "sre-group"
}

resource "aws_iam_group_policy" "sre_group_policy" {
  name  = "sre-access"
  group = aws_iam_group.sre_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SREMonitoring"
        Effect = "Allow"
        Action = [
          "cloudwatch:*",
          "logs:*",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ecs:DescribeServices",
          "ecs:ListTasks"
        ]
        Resource = "*"
      }
    ]
  })
}

# Admin group — benign
resource "aws_iam_group" "admin_group" {
  name = "admin-group"
}

resource "aws_iam_group_policy_attachment" "admin_full" {
  group      = aws_iam_group.admin_group.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# =============================================================================
# Users
# =============================================================================

# VULNERABLE: intern in readonly-support-group (inherits AssumeRole)
resource "aws_iam_user" "intern" {
  name = "intern"
  tags = { Lab = "lab05", Team = "support" }
}

resource "aws_iam_user_policy_attachment" "intern_discovery" {
  user       = aws_iam_user.intern.name
  policy_arn = aws_iam_policy.cloudspider_discovery.arn
}

resource "aws_iam_access_key" "intern_key" {
  user = aws_iam_user.intern.name
}

resource "aws_iam_user" "l1_support" {
  name = "l1-support"
  tags = { Lab = "lab05", Team = "support" }
}

resource "aws_iam_user" "l2_support" {
  name = "l2-support"
  tags = { Lab = "lab05", Team = "support" }
}

resource "aws_iam_group_membership" "support_members" {
  name  = "support-membership"
  group = aws_iam_group.readonly_support_group.name
  users = [
    aws_iam_user.intern.name,
    aws_iam_user.l1_support.name,
    aws_iam_user.l2_support.name,
  ]
}

# SRE team
resource "aws_iam_user" "sre_lead" {
  name = "sre-lead"
  tags = { Lab = "lab05", Team = "sre" }
}

resource "aws_iam_user" "sre_oncall" {
  name = "sre-oncall"
  tags = { Lab = "lab05", Team = "sre" }
}

resource "aws_iam_group_membership" "sre_members" {
  name  = "sre-membership"
  group = aws_iam_group.sre_group.name
  users = [
    aws_iam_user.sre_lead.name,
    aws_iam_user.sre_oncall.name,
  ]
}

# Admin & other users
resource "aws_iam_user" "platform_owner" {
  name = "platform-owner"
  tags = { Lab = "lab05", Team = "platform" }
}

resource "aws_iam_group_membership" "admin_members" {
  name  = "admin-membership"
  group = aws_iam_group.admin_group.name
  users = [
    aws_iam_user.platform_owner.name,
  ]
}

resource "aws_iam_user" "security_auditor" {
  name = "security-auditor"
  tags = { Lab = "lab05", Team = "security" }
}

resource "aws_iam_user_policy_attachment" "security_auditor_readonly" {
  user       = aws_iam_user.security_auditor.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_user" "billing_admin" {
  name = "billing-admin"
  tags = { Lab = "lab05", Team = "finance" }
}

resource "aws_iam_user_policy_attachment" "billing_admin_policy" {
  user       = aws_iam_user.billing_admin.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/Billing"
}

# =============================================================================
# Outputs
# =============================================================================

output "attack_path" {
  value = "intern (via readonly-support-group) --[ASSUME_ROLE]--> ops-admin-role"
}

output "vulnerable_principals" {
  value = [
    aws_iam_user.intern.arn,
    aws_iam_user.l1_support.arn,
    aws_iam_user.l2_support.arn,
  ]
}

output "target_role" {
  value = aws_iam_role.ops_admin_role.arn
}

output "cloudspider_access_key_id" {
  value       = aws_iam_access_key.intern_key.id
  description = "Access Key ID for CloudSpider"
}

output "cloudspider_secret_access_key" {
  value       = aws_iam_access_key.intern_key.secret
  sensitive   = true
  description = "Secret Access Key — retrieve with: terraform output -raw cloudspider_secret_access_key"
}
