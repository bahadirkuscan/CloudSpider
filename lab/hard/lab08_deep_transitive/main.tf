###############################################################################
# Lab 08 — Deep Transitive Chain (Hard)
#
# Vulnerability: A 5+ hop privilege escalation chain buried in a large
#                environment. Each hop looks benign in isolation — the
#                vulnerability only emerges through graph traversal.
#
#   junior-analyst → (group) AssumeRole → data-reader-role → PassRole →
#   etl-execution-role → UpdateFunctionCode → etl-processor Lambda →
#   lambda-admin-exec-role → AssumeRole → infrastructure-admin-role
#
# Scale: Large (15 users, 10 roles, 5 groups, 3 EC2, 2 Lambda, 2 S3, 1 RDS)
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

  tags = { Lab = "lab08" }
}

# =============================================================================
# S3 Buckets
# =============================================================================

resource "aws_s3_bucket" "data_lake" {
  bucket = "enterprise-data-lake-${local.account_id}"
  tags   = { Lab = "lab08" }
}

resource "aws_s3_bucket" "artifact_store" {
  bucket = "enterprise-artifact-store-${local.account_id}"
  tags   = { Lab = "lab08" }
}

# =============================================================================
# RDS Instance
# =============================================================================

resource "aws_db_instance" "analytics_db" {
  identifier           = "analytics-db"
  engine               = "postgres"
  engine_version       = "15"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "analytics_admin"
  password             = "LabPassword123!"
  skip_final_snapshot  = true

  tags = { Lab = "lab08" }
}

# =============================================================================
# ESCALATION CHAIN ROLES (Hops 1-5)
# =============================================================================

# Hop 1 target: data-reader-role (assumed via group policy)
resource "aws_iam_role" "data_reader_role" {
  name = "data-reader-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab08", Description = "Data read access" }
}

# data-reader-role: read S3 + PassRole to etl-execution-* (Hop 2)
resource "aws_iam_role_policy" "data_reader_base" {
  name = "data-reader-base"
  role = aws_iam_role.data_reader_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadDataLake"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.data_lake.arn,
          "${aws_s3_bucket.data_lake.arn}/*"
        ]
      },
      {
        Sid      = "ReadAthena"
        Effect   = "Allow"
        Action   = ["athena:StartQueryExecution", "athena:GetQueryResults", "athena:GetQueryExecution"]
        Resource = "*"
      },
      {
        Sid      = "PassRoleForETL"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::${local.account_id}:role/etl-execution-*"
      }
    ]
  })
}

# Hop 2-3: etl-execution-role (can update Lambda code)
resource "aws_iam_role" "etl_execution_role" {
  name = "etl-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab08", Description = "ETL pipeline execution" }
}

resource "aws_iam_role_policy" "etl_execution_policy" {
  name = "etl-execution-policy"
  role = aws_iam_role.etl_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ETLDataAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = "*"
      },
      {
        Sid    = "ManageLambdaPipeline"
        Effect = "Allow"
        Action = [
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:InvokeFunction",
          "lambda:GetFunction",
          "lambda:ListFunctions"
        ]
        Resource = "arn:aws:lambda:${var.region}:${local.account_id}:function:etl-*"
      },
      {
        Sid    = "GlueAccess"
        Effect = "Allow"
        Action = [
          "glue:StartJobRun",
          "glue:GetJobRun",
          "glue:GetJob"
        ]
        Resource = "*"
      }
    ]
  })
}

# Hop 4: lambda-admin-exec-role (Lambda execution role with broad access)
resource "aws_iam_role" "lambda_admin_exec_role" {
  name = "lambda-admin-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab08", Description = "Lambda exec with broad access" }
}

resource "aws_iam_role_policy" "lambda_admin_exec_policy" {
  name = "lambda-admin-exec-policy"
  role = aws_iam_role.lambda_admin_exec_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BroadDataAccess"
        Effect = "Allow"
        Action = [
          "s3:*",
          "dynamodb:*",
          "sqs:*",
          "sns:*",
          "logs:*"
        ]
        Resource = "*"
      },
      {
        Sid      = "CrossSystemManagement"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::${local.account_id}:role/infrastructure-*"
      }
    ]
  })
}

# Hop 5 target: infrastructure-admin-role (final target with full admin)
resource "aws_iam_role" "infrastructure_admin_role" {
  name = "infrastructure-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab08", Description = "Infrastructure admin - FINAL TARGET" }
}

resource "aws_iam_role_policy_attachment" "infrastructure_admin_full" {
  role       = aws_iam_role.infrastructure_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# =============================================================================
# NOISE ROLES (legitimate, non-vulnerable)
# =============================================================================

resource "aws_iam_role" "cloudwatch_exporter_role" {
  name = "cloudwatch-exporter-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab08" }
}

resource "aws_iam_role_policy_attachment" "cw_exporter" {
  role       = aws_iam_role.cloudwatch_exporter_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
}

resource "aws_iam_role" "config_recorder_role" {
  name = "config-recorder-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab08" }
}

resource "aws_iam_role" "guardduty_role" {
  name = "guardduty-detector-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "guardduty.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab08" }
}

resource "aws_iam_role" "backup_vault_role" {
  name = "backup-vault-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab08" }
}

resource "aws_iam_role" "event_processor_role" {
  name = "event-processor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab08" }
}

resource "aws_iam_role_policy_attachment" "event_processor_sqs" {
  role       = aws_iam_role.event_processor_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSQSFullAccess"
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

# Hop 3-4: etl-processor Lambda uses lambda-admin-exec-role
resource "aws_lambda_function" "etl_processor" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "etl-processor"
  role             = aws_iam_role.lambda_admin_exec_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256

  tags = { Lab = "lab08", Description = "ETL processor - uses admin exec role" }
}

# Benign Lambda
resource "aws_lambda_function" "event_handler" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "event-handler"
  role             = aws_iam_role.event_processor_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256

  tags = { Lab = "lab08" }
}

# =============================================================================
# EC2 Instances (noise)
# =============================================================================

resource "aws_instance" "web_server" {
  ami           = var.ami_id
  instance_type = "t3.micro"

  tags = { Name = "web-server", Lab = "lab08" }
}

resource "aws_instance" "batch_worker" {
  ami           = var.ami_id
  instance_type = "t3.micro"

  tags = { Name = "batch-worker", Lab = "lab08" }
}

resource "aws_instance" "analytics_node" {
  ami           = var.ami_id
  instance_type = "t3.micro"

  tags = { Name = "analytics-node", Lab = "lab08" }
}

# =============================================================================
# Groups
# =============================================================================

# ESCALATION CHAIN START: analytics-support-group with AssumeRole to data-reader-role
resource "aws_iam_group" "analytics_support_group" {
  name = "analytics-support-group"
}

resource "aws_iam_group_policy" "analytics_support_policy" {
  name  = "analytics-support-access"
  group = aws_iam_group.analytics_support_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AthenaReadOnly"
        Effect = "Allow"
        Action = [
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:ListQueryExecutions"
        ]
        Resource = "*"
      },
      {
        Sid      = "AssumeDataReaderRole"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.data_reader_role.arn
      }
    ]
  })
}

# Noise groups
resource "aws_iam_group" "platform_eng_group" {
  name = "platform-eng-group"
}

resource "aws_iam_group_policy" "platform_eng_policy" {
  name  = "platform-eng-access"
  group = aws_iam_group.platform_eng_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "PlatformTools"
      Effect = "Allow"
      Action = [
        "ecs:*",
        "ecr:*",
        "logs:*",
        "cloudwatch:*"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_group" "devops_group" {
  name = "devops-group"
}

resource "aws_iam_group_policy" "devops_policy" {
  name  = "devops-access"
  group = aws_iam_group.devops_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "InfraManagement"
      Effect = "Allow"
      Action = [
        "ec2:Describe*",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "elasticloadbalancing:*",
        "autoscaling:*"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_group" "security_group" {
  name = "security-audit-group"
}

resource "aws_iam_group_policy_attachment" "security_audit" {
  group      = aws_iam_group.security_group.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_group" "readonly_group" {
  name = "general-readonly-group"
}

resource "aws_iam_group_policy_attachment" "readonly_access" {
  group      = aws_iam_group.readonly_group.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# =============================================================================
# Users (15 total)
# =============================================================================

# VULNERABLE: junior-analyst (chain entry point)
resource "aws_iam_user" "junior_analyst" {
  name = "junior-analyst"
  tags = { Lab = "lab08", Team = "analytics" }
}

resource "aws_iam_user_policy_attachment" "junior_analyst_discovery" {
  user       = aws_iam_user.junior_analyst.name
  policy_arn = aws_iam_policy.cloudspider_discovery.arn
}

resource "aws_iam_access_key" "junior_analyst_key" {
  user = aws_iam_user.junior_analyst.name
}

resource "aws_iam_user" "senior_analyst" {
  name = "senior-analyst"
  tags = { Lab = "lab08", Team = "analytics" }
}

resource "aws_iam_user" "analytics_lead" {
  name = "analytics-lead"
  tags = { Lab = "lab08", Team = "analytics" }
}

resource "aws_iam_group_membership" "analytics_members" {
  name  = "analytics-membership"
  group = aws_iam_group.analytics_support_group.name
  users = [
    aws_iam_user.junior_analyst.name,
    aws_iam_user.senior_analyst.name,
    aws_iam_user.analytics_lead.name,
  ]
}

# Platform engineering team
resource "aws_iam_user" "platform_eng_1" {
  name = "platform-eng-1"
  tags = { Lab = "lab08", Team = "platform" }
}

resource "aws_iam_user" "platform_eng_2" {
  name = "platform-eng-2"
  tags = { Lab = "lab08", Team = "platform" }
}

resource "aws_iam_group_membership" "platform_members" {
  name  = "platform-membership"
  group = aws_iam_group.platform_eng_group.name
  users = [
    aws_iam_user.platform_eng_1.name,
    aws_iam_user.platform_eng_2.name,
  ]
}

# DevOps team
resource "aws_iam_user" "devops_1" {
  name = "devops-engineer-1"
  tags = { Lab = "lab08", Team = "devops" }
}

resource "aws_iam_user" "devops_2" {
  name = "devops-engineer-2"
  tags = { Lab = "lab08", Team = "devops" }
}

resource "aws_iam_user" "devops_lead" {
  name = "devops-lead"
  tags = { Lab = "lab08", Team = "devops" }
}

resource "aws_iam_group_membership" "devops_members" {
  name  = "devops-membership"
  group = aws_iam_group.devops_group.name
  users = [
    aws_iam_user.devops_1.name,
    aws_iam_user.devops_2.name,
    aws_iam_user.devops_lead.name,
  ]
}

# Security team
resource "aws_iam_user" "security_analyst_1" {
  name = "security-analyst-1"
  tags = { Lab = "lab08", Team = "security" }
}

resource "aws_iam_user" "security_analyst_2" {
  name = "security-analyst-2"
  tags = { Lab = "lab08", Team = "security" }
}

resource "aws_iam_group_membership" "security_members" {
  name  = "security-membership"
  group = aws_iam_group.security_group.name
  users = [
    aws_iam_user.security_analyst_1.name,
    aws_iam_user.security_analyst_2.name,
  ]
}

# Other users
resource "aws_iam_user" "product_owner" {
  name = "product-owner"
  tags = { Lab = "lab08", Team = "product" }
}

resource "aws_iam_user" "tech_writer" {
  name = "tech-writer"
  tags = { Lab = "lab08", Team = "docs" }
}

resource "aws_iam_user" "infra_admin" {
  name = "infra-admin-user"
  tags = { Lab = "lab08", Team = "infra" }
}

resource "aws_iam_user_policy_attachment" "infra_admin_full" {
  user       = aws_iam_user.infra_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_group_membership" "readonly_members" {
  name  = "readonly-membership"
  group = aws_iam_group.readonly_group.name
  users = [
    aws_iam_user.product_owner.name,
    aws_iam_user.tech_writer.name,
  ]
}

# =============================================================================
# Outputs
# =============================================================================

output "attack_chain" {
  value = [
    "Hop 1: junior-analyst (via analytics-support-group) --[ASSUME_ROLE]--> data-reader-role",
    "Hop 2: data-reader-role --[PASS_ROLE]--> etl-execution-role",
    "Hop 3: etl-execution-role --[CanUpdateFunction]--> etl-processor (Lambda)",
    "Hop 4: etl-processor executes as lambda-admin-exec-role",
    "Hop 5: lambda-admin-exec-role --[ASSUME_ROLE]--> infrastructure-admin-role (ADMIN)",
  ]
}

output "chain_entry_point" {
  value = aws_iam_user.junior_analyst.arn
}

output "chain_final_target" {
  value = aws_iam_role.infrastructure_admin_role.arn
}

output "total_resources" {
  value = "15 users, 10 roles, 5 groups, 3 EC2, 2 Lambda, 2 S3, 1 RDS"
}

output "cloudspider_access_key_id" {
  value       = aws_iam_access_key.junior_analyst_key.id
  description = "Access Key ID for CloudSpider"
}

output "cloudspider_secret_access_key" {
  value       = aws_iam_access_key.junior_analyst_key.secret
  sensitive   = true
  description = "Secret Access Key — retrieve with: terraform output -raw cloudspider_secret_access_key"
}
