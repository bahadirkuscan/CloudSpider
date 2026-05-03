###############################################################################
# Lab 02 — Direct AssumeRole (Easy)
#
# Vulnerability: analyst user has sts:AssumeRole on *, enabling direct
#                assumption of the full-admin-role.
#
# Scale: Small (2 users, 2 roles)
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
        Action = [
          "iam:List*", "iam:Get*"
        ]
        Resource = "*"
      },
      {
        Sid    = "ResourceDiscovery"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "ec2:DescribeInstances",
          "lambda:ListFunctions", "lambda:GetFunction",
          "rds:DescribeDBInstances",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      }
    ]
  })

  tags = { Lab = "lab02" }
}

# =============================================================================
# Full Admin Role — target
# =============================================================================

resource "aws_iam_role" "full_admin_role" {
  name = "full-admin-role"

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

  tags = {
    Lab         = "lab02"
    Description = "Full admin role - target"
  }
}

resource "aws_iam_role_policy_attachment" "admin_role_full" {
  role       = aws_iam_role.full_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# =============================================================================
# Data Pipeline Role — benign noise
# =============================================================================

resource "aws_iam_role" "data_pipeline_role" {
  name = "data-pipeline-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "datapipeline.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Lab         = "lab02"
    Description = "Data pipeline execution role - benign"
  }
}

resource "aws_iam_role_policy_attachment" "pipeline_s3" {
  role       = aws_iam_role.data_pipeline_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# =============================================================================
# Analyst User — VULNERABLE (sts:AssumeRole on *)
# =============================================================================

resource "aws_iam_user" "analyst" {
  name = "analyst"

  tags = {
    Lab         = "lab02"
    Description = "Data analyst - vulnerable"
  }
}

resource "aws_iam_user_policy_attachment" "analyst_discovery" {
  user       = aws_iam_user.analyst.name
  policy_arn = aws_iam_policy.cloudspider_discovery.arn
}

resource "aws_iam_access_key" "analyst_key" {
  user = aws_iam_user.analyst.name
}

# Legitimate read-only permissions
resource "aws_iam_user_policy" "analyst_readonly" {
  name = "analyst-readonly"
  user = aws_iam_user.analyst.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyAthena"
        Effect = "Allow"
        Action = [
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StartQueryExecution"
        ]
        Resource = "*"
      },
      {
        Sid    = "ReadOnlyS3"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = "*"
      }
    ]
  })
}

# VULNERABILITY: AssumeRole on wildcard
resource "aws_iam_user_policy" "analyst_assume_any" {
  name = "analyst-cross-account-access"
  user = aws_iam_user.analyst.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CrossAccountAccess"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# Finance Viewer — benign noise
# =============================================================================

resource "aws_iam_user" "finance_viewer" {
  name = "finance-viewer"

  tags = {
    Lab         = "lab02"
    Description = "Finance team read-only - benign"
  }
}

resource "aws_iam_user_policy_attachment" "finance_readonly" {
  user       = aws_iam_user.finance_viewer.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# =============================================================================
# Outputs
# =============================================================================

output "attack_path" {
  value = "analyst --[ASSUME_ROLE]--> full-admin-role"
}

output "vulnerable_principal" {
  value = aws_iam_user.analyst.arn
}

output "target_principal" {
  value = aws_iam_role.full_admin_role.arn
}

output "cloudspider_access_key_id" {
  value       = aws_iam_access_key.analyst_key.id
  description = "Access Key ID for CloudSpider"
}

output "cloudspider_secret_access_key" {
  value       = aws_iam_access_key.analyst_key.secret
  sensitive   = true
  description = "Secret Access Key — retrieve with: terraform output -raw cloudspider_secret_access_key"
}
