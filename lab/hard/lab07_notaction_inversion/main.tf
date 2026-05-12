###############################################################################
# Lab 07 — NotAction Deny Inversion (Hard)
#
# Vulnerability: support-agent has a NotAction Allow that inadvertently
#                grants sts:AssumeRole. A companion Deny with NotResource
#                only blocks iam:* actions, not sts:*, leaving the
#                AssumeRole path open to privileged-deploy-role.
#
# Scale: Large (12 users, 6 roles, 4 groups, 3 Lambdas, 2 S3 buckets)
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

  tags = { Lab = "lab07" }
}

# =============================================================================
# S3 Buckets
# =============================================================================

resource "aws_s3_bucket" "data_lake" {
  bucket = "company-data-lake-${local.account_id}"
  tags   = { Lab = "lab07" }
}

resource "aws_s3_bucket" "deploy_artifacts" {
  bucket = "deployment-artifacts-${local.account_id}"
  tags   = { Lab = "lab07" }
}

# =============================================================================
# Roles
# =============================================================================

# TARGET: privileged deployment role with admin access
resource "aws_iam_role" "privileged_deploy_role" {
  name = "privileged-deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = { Lab = "lab07", Description = "Deployment role - admin" }
}

resource "aws_iam_role_policy_attachment" "privileged_deploy_admin" {
  role       = aws_iam_role.privileged_deploy_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Benign roles
resource "aws_iam_role" "lambda_data_role" {
  name = "lambda-data-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab07" }
}

resource "aws_iam_role_policy_attachment" "lambda_data_s3" {
  role       = aws_iam_role.lambda_data_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_role" "lambda_api_role" {
  name = "lambda-api-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab07" }
}

resource "aws_iam_role_policy_attachment" "lambda_api_exec" {
  role       = aws_iam_role.lambda_api_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "glue_etl_role" {
  name = "glue-etl-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "glue.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab07" }
}

resource "aws_iam_role_policy_attachment" "glue_service" {
  role       = aws_iam_role.glue_etl_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role" "readonly_audit_role" {
  name = "readonly-audit-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab07" }
}

resource "aws_iam_role_policy_attachment" "readonly_audit" {
  role       = aws_iam_role.readonly_audit_role.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role" "cost_analysis_role" {
  name = "cost-analysis-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "budgets.amazonaws.com" } # Updated valid service principal
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab07" }
}

# =============================================================================
# Lambda Functions
# =============================================================================

data "archive_file" "dummy_lambda" {
  type        = "zip"
  output_path = "${path.module}/lambda_placeholder.zip"

  source {
    content  = "def handler(event, context): return {'statusCode': 200}"
    filename = "index.py"
  }
}

resource "aws_lambda_function" "api_gateway_handler" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "api-gateway-handler"
  role             = aws_iam_role.lambda_api_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256

  tags = { Lab = "lab07" }
}

resource "aws_lambda_function" "data_ingest" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "data-ingest"
  role             = aws_iam_role.lambda_data_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256

  tags = { Lab = "lab07" }
}

resource "aws_lambda_function" "alert_notifier" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "alert-notifier"
  role             = aws_iam_role.lambda_api_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256

  tags = { Lab = "lab07" }
}

# =============================================================================
# Groups
# =============================================================================

resource "aws_iam_group" "support_team" {
  name = "support-team"
}

resource "aws_iam_group_policy" "support_team_base" {
  name  = "support-base"
  group = aws_iam_group.support_team.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SupportTools"
      Effect = "Allow"
      Action = [
        "support:*",
        "trustedadvisor:*",
        "health:Describe*"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_group" "engineering_team" {
  name = "engineering-team"
}

resource "aws_iam_group_policy" "engineering_base" {
  name  = "engineering-base"
  group = aws_iam_group.engineering_team.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DevTools"
      Effect = "Allow"
      Action = [
        "codecommit:*",
        "codebuild:*",
        "logs:*",
        "cloudwatch:GetMetricData",
        "cloudwatch:ListMetrics"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_group" "data_team" {
  name = "data-team"
}

resource "aws_iam_group_policy" "data_base" {
  name  = "data-base"
  group = aws_iam_group.data_team.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DataAccess"
      Effect = "Allow"
      Action = [
        "athena:*",
        "glue:Get*",
        "glue:BatchGet*",
        "s3:GetObject",
        "s3:ListBucket"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_group" "readonly_team" {
  name = "readonly-team"
}

resource "aws_iam_group_policy_attachment" "readonly_policy" {
  group      = aws_iam_group.readonly_team.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# =============================================================================
# Users
# =============================================================================

# VULNERABLE: support-agent with NotAction Allow + NotResource Deny
resource "aws_iam_user" "support_agent" {
  name = "support-agent"
  tags = { Lab = "lab07", Team = "support" }
}

resource "aws_iam_user_policy_attachment" "support_agent_discovery" {
  user       = aws_iam_user.support_agent.name
  policy_arn = aws_iam_policy.cloudspider_discovery.arn
}

resource "aws_iam_access_key" "support_agent_key" {
  user = aws_iam_user.support_agent.name
}

# VULNERABILITY: NotAction Allow inadvertently grants sts:AssumeRole
resource "aws_iam_user_policy" "support_agent_notaction" {
  name = "support-agent-access"
  user = aws_iam_user.support_agent.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowNonOrgActions"
        Effect    = "Allow"
        NotAction = [
          "organizations:*",
          "account:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenySensitiveResources"
        Effect = "Deny"
        Action = [
          "iam:Create*",
          "iam:Delete*",
          "iam:Put*",
          "iam:Update*",
          "iam:Attach*",
          "iam:Detach*",
          "iam:Add*",
          "iam:Remove*",
          "iam:Set*",
          "iam:Change*",
          "iam:PassRole",
          "iam:CreateServiceLinkedRole",
          "iam:TagRole",
          "iam:UntagRole"
        ]
        NotResource = [
          "arn:aws:iam::${local.account_id}:user/support-*",
          "arn:aws:iam::${local.account_id}:role/readonly-*"
        ]
      }
    ]
  })
}

# Other support users
resource "aws_iam_user" "support_lead" {
  name = "support-lead"
  tags = { Lab = "lab07", Team = "support" }
}

resource "aws_iam_user" "support_manager" {
  name = "support-manager"
  tags = { Lab = "lab07", Team = "support" }
}

resource "aws_iam_group_membership" "support_members" {
  name  = "support-membership"
  group = aws_iam_group.support_team.name
  users = [
    aws_iam_user.support_agent.name,
    aws_iam_user.support_lead.name,
    aws_iam_user.support_manager.name,
  ]
}

# Engineering users
resource "aws_iam_user" "backend_eng_1" {
  name = "backend-eng-1"
  tags = { Lab = "lab07", Team = "engineering" }
}

resource "aws_iam_user" "backend_eng_2" {
  name = "backend-eng-2"
  tags = { Lab = "lab07", Team = "engineering" }
}

resource "aws_iam_user" "backend_eng_3" {
  name = "backend-eng-3"
  tags = { Lab = "lab07", Team = "engineering" }
}

resource "aws_iam_group_membership" "engineering_members" {
  name  = "engineering-membership"
  group = aws_iam_group.engineering_team.name
  users = [
    aws_iam_user.backend_eng_1.name,
    aws_iam_user.backend_eng_2.name,
    aws_iam_user.backend_eng_3.name,
  ]
}

# Data team users
resource "aws_iam_user" "data_eng_1" {
  name = "data-eng-1"
  tags = { Lab = "lab07", Team = "data" }
}

resource "aws_iam_user" "data_eng_2" {
  name = "data-eng-2"
  tags = { Lab = "lab07", Team = "data" }
}

resource "aws_iam_group_membership" "data_members" {
  name  = "data-membership"
  group = aws_iam_group.data_team.name
  users = [
    aws_iam_user.data_eng_1.name,
    aws_iam_user.data_eng_2.name,
  ]
}

# Admin & security users
resource "aws_iam_user" "infra_admin" {
  name = "infra-admin"
  tags = { Lab = "lab07", Team = "infra" }
}

resource "aws_iam_user_policy_attachment" "infra_admin_full" {
  user       = aws_iam_user.infra_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "security_ops" {
  name = "security-ops"
  tags = { Lab = "lab07", Team = "security" }
}

resource "aws_iam_user_policy_attachment" "security_ops_audit" {
  user       = aws_iam_user.security_ops.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_user" "product_manager" {
  name = "product-manager"
  tags = { Lab = "lab07", Team = "product" }
}

resource "aws_iam_group_membership" "readonly_members" {
  name  = "readonly-membership"
  group = aws_iam_group.readonly_team.name
  users = [
    aws_iam_user.product_manager.name,
  ]
}

# =============================================================================
# Outputs
# =============================================================================

output "attack_path" {
  value = "support-agent --[ASSUME_ROLE (via NotAction Allow)]--> privileged-deploy-role"
}

output "vulnerability_explanation" {
  value = "NotAction excludes organizations:* and account:* but NOT sts:*. The Deny blocks iam:* but not sts:AssumeRole."
}

output "vulnerable_principal" {
  value = aws_iam_user.support_agent.arn
}

output "target_role" {
  value = aws_iam_role.privileged_deploy_role.arn
}

output "cloudspider_access_key_id" {
  value       = aws_iam_access_key.support_agent_key.id
  description = "Access Key ID for CloudSpider"
}

output "cloudspider_secret_access_key" {
  value       = aws_iam_access_key.support_agent_key.secret
  sensitive   = true
  description = "Secret Access Key — retrieve with: terraform output -raw cloudspider_secret_access_key"
}
