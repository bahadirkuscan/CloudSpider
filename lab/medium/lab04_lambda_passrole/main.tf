###############################################################################
# Lab 04 — Lambda PassRole Chain (Medium)
#
# Vulnerability: ci-deploy user can UpdateFunctionCode on Lambda functions
#                AND PassRole to the lambda-exec-admin-role, enabling code
#                injection into a Lambda that executes with admin privileges.
#
# Scale: Medium (3 users, 3 roles, 2 Lambda functions)
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

  tags = { Lab = "lab04" }
}

# =============================================================================
# Lambda Execution Roles
# =============================================================================

# VULNERABLE TARGET: Lambda exec role with admin access
resource "aws_iam_role" "lambda_exec_admin" {
  name = "lambda-exec-admin-role"

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

  tags = { Lab = "lab04", Description = "Lambda exec role - ADMIN" }
}

resource "aws_iam_role_policy_attachment" "lambda_exec_admin_policy" {
  role       = aws_iam_role.lambda_exec_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Benign: read-only Lambda exec role
resource "aws_iam_role" "lambda_exec_readonly" {
  name = "lambda-exec-readonly-role"

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

  tags = { Lab = "lab04", Description = "Lambda exec role - readonly" }
}

resource "aws_iam_role_policy_attachment" "lambda_exec_readonly_policy" {
  role       = aws_iam_role.lambda_exec_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "lambda_exec_readonly_logs" {
  role       = aws_iam_role.lambda_exec_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Benign: Glue crawler role
resource "aws_iam_role" "glue_crawler_role" {
  name = "glue-crawler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "glue.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = { Lab = "lab04" }
}

resource "aws_iam_role_policy_attachment" "glue_s3" {
  role       = aws_iam_role.glue_crawler_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# =============================================================================
# Lambda Functions
# =============================================================================

# Placeholder zip for Lambda deployment
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
  function_name    = "data-processor"
  role             = aws_iam_role.lambda_exec_admin.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256

  tags = { Lab = "lab04", Description = "ETL data processor - uses admin role" }
}

resource "aws_lambda_function" "log_aggregator" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "log-aggregator"
  role             = aws_iam_role.lambda_exec_readonly.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256

  tags = { Lab = "lab04", Description = "Log aggregator - read-only role" }
}

# =============================================================================
# CI/CD Deploy User — VULNERABLE
# =============================================================================

resource "aws_iam_user" "ci_deploy" {
  name = "ci-deploy"
  tags = { Lab = "lab04", Role = "cicd" }
}

resource "aws_iam_user_policy_attachment" "ci_deploy_discovery" {
  user       = aws_iam_user.ci_deploy.name
  policy_arn = aws_iam_policy.cloudspider_discovery.arn
}

resource "aws_iam_access_key" "ci_deploy_key" {
  user = aws_iam_user.ci_deploy.name
}

# Lambda deployment permissions
resource "aws_iam_user_policy" "ci_deploy_lambda" {
  name = "ci-deploy-lambda"
  user = aws_iam_user.ci_deploy.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LambdaDeploy"
        Effect = "Allow"
        Action = [
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:GetFunction",
          "lambda:ListFunctions"
        ]
        Resource = "arn:aws:lambda:${var.region}:${data.aws_caller_identity.current.account_id}:function:*"
      }
    ]
  })
}

# VULNERABILITY: PassRole to any lambda-exec-* role (includes admin role)
resource "aws_iam_user_policy" "ci_deploy_passrole" {
  name = "ci-deploy-passrole"
  user = aws_iam_user.ci_deploy.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PassRoleForLambda"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/lambda-exec-*"
      }
    ]
  })
}

# S3 read for artifact retrieval
resource "aws_iam_user_policy" "ci_deploy_s3" {
  name = "ci-deploy-s3-artifacts"
  user = aws_iam_user.ci_deploy.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadArtifacts"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# Benign Users
# =============================================================================

resource "aws_iam_user" "data_scientist" {
  name = "data-scientist"
  tags = { Lab = "lab04", Team = "data" }
}

resource "aws_iam_user_policy_attachment" "data_scientist_athena" {
  user       = aws_iam_user.data_scientist.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonAthenaFullAccess"
}

resource "aws_iam_user" "ml_engineer" {
  name = "ml-engineer"
  tags = { Lab = "lab04", Team = "ml" }
}

resource "aws_iam_user_policy_attachment" "ml_engineer_sagemaker" {
  user       = aws_iam_user.ml_engineer.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerReadOnly"
}

# =============================================================================
# Outputs
# =============================================================================

output "attack_path" {
  value = "ci-deploy --[CanUpdateFunction]--> data-processor (Lambda) <--[exec role]--> lambda-exec-admin-role"
}

output "vulnerable_principal" {
  value = aws_iam_user.ci_deploy.arn
}

output "target_lambda" {
  value = aws_lambda_function.data_processor.arn
}

output "target_role" {
  value = aws_iam_role.lambda_exec_admin.arn
}

output "cloudspider_access_key_id" {
  value       = aws_iam_access_key.ci_deploy_key.id
  description = "Access Key ID for CloudSpider"
}

output "cloudspider_secret_access_key" {
  value       = aws_iam_access_key.ci_deploy_key.secret
  sensitive   = true
  description = "Secret Access Key — retrieve with: terraform output -raw cloudspider_secret_access_key"
}
