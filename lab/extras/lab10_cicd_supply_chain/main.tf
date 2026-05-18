###############################################################################
# Lab 10 — Self-Service Policy Tampering (Medium)
#
# Theme:    Realistic SaaS engineering org ("Acme Cloud") whose QA team has
#           been granted self-service IAM management for its own group and
#           orchestration roles. Three layered IAM-only misconfigurations
#           chain into administrator access.
#
# Chain:    qa-automation-engineer-3
#             └─ iam:PutGroupPolicy on qa-automation-team
#                └─ writes inline policy granting sts:AssumeRole
#                   on qa-platform-orchestrator-role
#                   └─ sts:AssumeRole → qa-platform-orchestrator-role
#                      └─ iam:AttachRolePolicy on qa-integration-service-role
#                         └─ attaches AdministratorAccess
#                            └─ sts:AssumeRole → qa-integration-service-role
#                               └─ Full administrative access
#
# Attack vectors (all pure IAM-policy primitives):
#   1. iam:PutGroupPolicy on an attacker-membership group (group-inline backdoor)
#   2. Group-inherited sts:AssumeRole
#   3. iam:AttachRolePolicy with unconstrained PolicyArn
#   4. sts:AssumeRole on the now-administrator-attached role
#
# Progressive visibility: tag-scoped discovery so the initial user only sees
# its own Team=qa-automation slice of the environment; assuming each role
# along the chain unlocks broader IAM read.
#
# Scale:    Medium (~30 users, 14 roles, 6 groups, 3 Lambda, 3 EC2, 2 S3)
###############################################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
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
  description = "AMI ID for noise EC2 instances"
  type        = string
  default     = "ami-0c02fb55956c7d316"
}

data "aws_caller_identity" "current" {}
locals {
  account_id = data.aws_caller_identity.current.account_id
}

# =============================================================================
# Discovery policies (tag-scoped, progressive)
# =============================================================================

resource "aws_iam_policy" "discovery_qa_automation" {
  name = "discovery-team-qa-automation"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListNamesOnly"
        Effect = "Allow"
        Action = [
          "iam:ListUsers", "iam:ListRoles", "iam:ListGroups",
          "iam:ListPolicies", "iam:ListInstanceProfiles",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      },
      {
        Sid    = "ReadOwnTeamIAM"
        Effect = "Allow"
        Action = [
          "iam:GetUser", "iam:GetRole", "iam:GetGroup",
          "iam:GetPolicy", "iam:GetPolicyVersion",
          "iam:GetUserPolicy", "iam:GetRolePolicy", "iam:GetGroupPolicy",
          "iam:ListUserPolicies", "iam:ListAttachedUserPolicies",
          "iam:ListRolePolicies", "iam:ListAttachedRolePolicies",
          "iam:ListGroupPolicies", "iam:ListAttachedGroupPolicies",
          "iam:ListGroupsForUser", "iam:ListPolicyVersions",
          "iam:ListEntitiesForPolicy"
        ]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:ResourceTag/Team" = "qa-automation" }
        }
      },
      {
        Sid    = "MinimalResourceDiscovery"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "ec2:DescribeInstances", "ec2:DescribeTags",
          "lambda:ListFunctions",
          "tag:GetResources"
        ]
        Resource = "*"
      }
    ]
  })

  tags = { Lab = "lab10" }
}

resource "aws_iam_policy" "discovery_qa_platform" {
  name = "discovery-team-qa-platform"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListNamesOnly"
        Effect = "Allow"
        Action = [
          "iam:ListUsers", "iam:ListRoles", "iam:ListGroups",
          "iam:ListPolicies", "iam:ListInstanceProfiles",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      },
      {
        Sid    = "ReadQAResources"
        Effect = "Allow"
        Action = [
          "iam:Get*",
          "iam:ListUserPolicies", "iam:ListAttachedUserPolicies",
          "iam:ListRolePolicies", "iam:ListAttachedRolePolicies",
          "iam:ListGroupPolicies", "iam:ListAttachedGroupPolicies",
          "iam:ListGroupsForUser", "iam:ListPolicyVersions",
          "iam:ListEntitiesForPolicy"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Team" = ["qa-automation", "qa-platform"]
          }
        }
      },
      {
        Sid    = "ResourceDiscovery"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "ec2:Describe*",
          "lambda:ListFunctions",
          "tag:GetResources"
        ]
        Resource = "*"
      }
    ]
  })

  tags = { Lab = "lab10" }
}

# =============================================================================
# S3 buckets (noise — never read or written during the chain)
# =============================================================================

resource "aws_s3_bucket" "qa_automation_artifacts" {
  bucket        = "acme-qa-automation-artifacts-${local.account_id}"
  force_destroy = true
  tags          = { Lab = "lab10", Team = "qa-automation" }
}

resource "aws_s3_bucket" "qa_platform_builds" {
  bucket        = "acme-qa-platform-builds-${local.account_id}"
  force_destroy = true
  tags          = { Lab = "lab10", Team = "qa-platform" }
}

# =============================================================================
# Chain Hop 1 → 2 — qa-platform-orchestrator-role
# =============================================================================
#
# Once the entry user backdoors the qa-automation-team's inline policy with
# sts:AssumeRole on qa-platform-orchestrator-role, every member of the team
# (including the entry user) can assume the orchestrator. The orchestrator
# in turn holds iam:AttachRolePolicy on qa-integration-service-role with
# NO PolicyArn restriction.
# =============================================================================

resource "aws_iam_role" "qa_platform_orchestrator_role" {
  name = "qa-platform-orchestrator-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab10", Team = "qa-platform", Description = "Orchestrator - vulnerable" }
}

resource "aws_iam_role_policy_attachment" "qa_platform_orchestrator_discovery" {
  role       = aws_iam_role.qa_platform_orchestrator_role.name
  policy_arn = aws_iam_policy.discovery_qa_platform.arn
}

# Legitimate-looking baseline: orchestrator reads pipeline metadata + can
# assume the integration role for normal QA tasks.
resource "aws_iam_role_policy" "qa_platform_orchestrator_baseline" {
  name = "qa-platform-orchestrator-baseline"
  role = aws_iam_role.qa_platform_orchestrator_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadPipelineState"
        Effect = "Allow"
        Action = [
          "s3:GetObject", "s3:ListBucket",
          "codepipeline:GetPipelineState", "codepipeline:ListPipelineExecutions",
          "logs:DescribeLogGroups", "logs:GetLogEvents"
        ]
        Resource = "*"
      },
      {
        Sid      = "AssumeIntegrationRole"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.qa_integration_service_role.arn
      }
    ]
  })
}

# VULNERABLE: orchestrator can attach ANY managed policy to the integration role.
#
# *Justification*: the orchestrator role is supposed to provision the right
# QA-scoped managed policy onto qa-integration-service-role as test fixtures
# evolve. There is no PolicyArn restriction — `AdministratorAccess` is
# trivially within scope.
resource "aws_iam_role_policy" "qa_platform_orchestrator_attach" {
  name = "qa-platform-orchestrator-policy-management"
  role = aws_iam_role.qa_platform_orchestrator_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ManageIntegrationRoleAttachments"
      Effect = "Allow"
      Action = [
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:ListAttachedRolePolicies"
      ]
      Resource = aws_iam_role.qa_integration_service_role.arn
    }]
  })
}

# =============================================================================
# Chain Hop 3 → 4 → 5 — qa-integration-service-role (final target)
# =============================================================================
#
# qa-integration-service-role normally carries only a narrow self-service
# policy. After the orchestrator attaches AdministratorAccess, anyone who
# can assume this role becomes account admin — and the orchestrator has
# been pre-authorised in the trust policy.
# =============================================================================

resource "aws_iam_role" "qa_integration_service_role" {
  name = "qa-integration-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.qa_platform_orchestrator_role.arn }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab10", Team = "qa-platform", Description = "FINAL TARGET" }
}

resource "aws_iam_policy" "qa_integration_baseline" {
  name = "QAIntegrationBaselinePolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject", "s3:PutObject", "s3:ListBucket",
        "dynamodb:GetItem", "dynamodb:Query",
        "logs:CreateLogStream", "logs:PutLogEvents"
      ]
      Resource = "*"
    }]
  })

  tags = { Lab = "lab10", Team = "qa-platform" }
}

resource "aws_iam_role_policy_attachment" "qa_integration_baseline_attach" {
  role       = aws_iam_role.qa_integration_service_role.name
  policy_arn = aws_iam_policy.qa_integration_baseline.arn
}

# =============================================================================
# Noise roles (legitimate, non-vulnerable)
# =============================================================================

resource "aws_iam_role" "qa_smoke_test_role" {
  name = "qa-smoke-test-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab10", Team = "qa-platform" }
}

resource "aws_iam_role_policy" "qa_smoke_test_inline" {
  name = "qa-smoke-test-inline"
  role = aws_iam_role.qa_smoke_test_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:*", "s3:GetObject", "s3:ListBucket"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "qa_report_lambda_role" {
  name = "qa-automation-report-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab10", Team = "qa-automation" }
}

resource "aws_iam_role_policy_attachment" "qa_report_logs" {
  role       = aws_iam_role.qa_report_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "platform_alerts_role" {
  name = "platform-alerts-router-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Lab = "lab10", Team = "infrastructure" }
}

resource "aws_iam_role_policy_attachment" "platform_alerts_logs" {
  role       = aws_iam_role.platform_alerts_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

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
  tags = { Lab = "lab10", Team = "infrastructure" }
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
  tags = { Lab = "lab10", Team = "security" }
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
  tags = { Lab = "lab10", Team = "security" }
}

resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs-task-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab10", Team = "infrastructure" }
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_managed" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
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
  tags = { Lab = "lab10", Team = "infrastructure" }
}

resource "aws_iam_role" "frontend_deploy_role" {
  name = "frontend-deploy-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab10", Team = "engineering" }
}

resource "aws_iam_role_policy" "frontend_deploy_inline" {
  name = "frontend-deploy-inline"
  role = aws_iam_role.frontend_deploy_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "cloudfront:CreateInvalidation"]
      Resource = "*"
    }]
  })
}

# =============================================================================
# Noise Lambda functions (no env-var secrets — pure scaffolding)
# =============================================================================

data "archive_file" "dummy_lambda" {
  type        = "zip"
  output_path = "${path.module}/lambda_placeholder.zip"
  source {
    content  = "def handler(event, context):\n    return {'statusCode': 200}\n"
    filename = "index.py"
  }
}

resource "aws_lambda_function" "qa_report_generator" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "qa-automation-report-generator"
  role             = aws_iam_role.qa_report_lambda_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256
  tags             = { Lab = "lab10", Team = "qa-automation" }
}

resource "aws_lambda_function" "platform_alerts_router" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "platform-alerts-router"
  role             = aws_iam_role.platform_alerts_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256
  tags             = { Lab = "lab10", Team = "infrastructure" }
}

resource "aws_lambda_function" "backend_event_consumer" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "backend-event-consumer"
  role             = aws_iam_role.platform_alerts_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256
  tags             = { Lab = "lab10", Team = "engineering" }
}

# =============================================================================
# EC2 noise
# =============================================================================

resource "aws_instance" "ci_runner_host_1" {
  ami           = var.ami_id
  instance_type = "t3.micro"
  tags          = { Name = "ci-runner-host-01", Lab = "lab10", Team = "qa-platform" }
}

resource "aws_instance" "ci_runner_host_2" {
  ami           = var.ami_id
  instance_type = "t3.micro"
  tags          = { Name = "ci-runner-host-02", Lab = "lab10", Team = "qa-platform" }
}

resource "aws_instance" "internal_tools_host" {
  ami           = var.ami_id
  instance_type = "t3.micro"
  tags          = { Name = "internal-tools-host", Lab = "lab10", Team = "infrastructure" }
}

# =============================================================================
# Groups
# =============================================================================

resource "aws_iam_group" "qa_automation_team" {
  name = "qa-automation-team"
}

resource "aws_iam_group_policy" "qa_automation_team_baseline" {
  name  = "qa-automation-team-baseline"
  group = aws_iam_group.qa_automation_team.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ReadOwnTeamArtifacts"
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
      Resource = [
        aws_s3_bucket.qa_automation_artifacts.arn,
        "${aws_s3_bucket.qa_automation_artifacts.arn}/*"
      ]
    }]
  })
}

resource "aws_iam_group" "qa_platform_team" {
  name = "qa-platform-team"
}

resource "aws_iam_group_policy" "qa_platform_team_baseline" {
  name  = "qa-platform-team-baseline"
  group = aws_iam_group.qa_platform_team.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["codebuild:BatchGetProjects", "codebuild:ListProjects", "ec2:Describe*"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_group" "engineering_team" {
  name = "engineering-team"
}

resource "aws_iam_group_policy_attachment" "engineering_readonly" {
  group      = aws_iam_group.engineering_team.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_group" "devops_team" {
  name = "devops-team"
}

resource "aws_iam_group_policy" "devops_team_policy" {
  name  = "devops-team-policy"
  group = aws_iam_group.devops_team.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:*", "elasticloadbalancing:*", "autoscaling:*", "ecs:*", "logs:*"]
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

resource "aws_iam_group" "data_engineering_team" {
  name = "data-engineering-team"
}

resource "aws_iam_group_policy" "data_eng_policy" {
  name  = "data-engineering-policy"
  group = aws_iam_group.data_engineering_team.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["glue:*", "athena:*", "s3:GetObject", "s3:ListBucket"]
      Resource = "*"
    }]
  })
}

# =============================================================================
# Users (~30 total)
# =============================================================================

# CHAIN ENTRY — qa-automation-engineer-3
resource "aws_iam_user" "qa_automation_engineer_3" {
  name = "qa-automation-engineer-3"
  tags = { Lab = "lab10", Team = "qa-automation", Role = "chain-entry" }
}

resource "aws_iam_user_policy_attachment" "qa_auto_eng_3_discovery" {
  user       = aws_iam_user.qa_automation_engineer_3.name
  policy_arn = aws_iam_policy.discovery_qa_automation.arn
}

# VULNERABLE: chain entry user can write inline policies on its own team's group.
#
# *Justification*: a "QA self-service" delegation lets team leads iterate
# on the group's permissions without filing IAM tickets. The resource is
# tightly scoped to the team's group ARN — looks defensible — but inline
# policies can grant ANY action, including sts:AssumeRole on out-of-team
# roles like qa-platform-orchestrator-role.
resource "aws_iam_user_policy" "qa_auto_eng_3_group_self_service" {
  name = "qa-automation-engineer-3-group-self-service"
  user = aws_iam_user.qa_automation_engineer_3.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ManageOwnTeamGroupPolicy"
      Effect = "Allow"
      Action = [
        "iam:PutGroupPolicy",
        "iam:DeleteGroupPolicy",
        "iam:GetGroupPolicy",
        "iam:ListGroupPolicies"
      ]
      Resource = aws_iam_group.qa_automation_team.arn
    }]
  })
}

resource "aws_iam_access_key" "qa_automation_engineer_3_key" {
  user = aws_iam_user.qa_automation_engineer_3.name
}

# Other QA automation users
resource "aws_iam_user" "qa_automation_others" {
  for_each = toset([
    "qa-automation-engineer-1", "qa-automation-engineer-2",
    "qa-automation-engineer-4", "qa-automation-lead"
  ])
  name = each.value
  tags = { Lab = "lab10", Team = "qa-automation" }
}

resource "aws_iam_group_membership" "qa_automation_members" {
  name  = "qa-automation-team-membership"
  group = aws_iam_group.qa_automation_team.name
  users = concat(
    [aws_iam_user.qa_automation_engineer_3.name],
    [for u in aws_iam_user.qa_automation_others : u.name]
  )
}

resource "aws_iam_user" "qa_platform_users" {
  for_each = toset([
    "qa-platform-engineer-1", "qa-platform-engineer-2", "qa-platform-engineer-3",
    "qa-platform-lead", "qa-release-coordinator"
  ])
  name = each.value
  tags = { Lab = "lab10", Team = "qa-platform" }
}

resource "aws_iam_group_membership" "qa_platform_members" {
  name  = "qa-platform-team-membership"
  group = aws_iam_group.qa_platform_team.name
  users = [for u in aws_iam_user.qa_platform_users : u.name]
}

resource "aws_iam_user" "engineering_users" {
  for_each = toset([
    "backend-engineer-1", "backend-engineer-2", "backend-engineer-3",
    "frontend-engineer-1", "frontend-engineer-2", "engineering-manager"
  ])
  name = each.value
  tags = { Lab = "lab10", Team = "engineering" }
}

resource "aws_iam_group_membership" "engineering_members" {
  name  = "engineering-team-membership"
  group = aws_iam_group.engineering_team.name
  users = [for u in aws_iam_user.engineering_users : u.name]
}

resource "aws_iam_user" "devops_users" {
  for_each = toset(["devops-engineer-1", "devops-engineer-2", "devops-lead"])
  name     = each.value
  tags     = { Lab = "lab10", Team = "infrastructure" }
}

resource "aws_iam_group_membership" "devops_members" {
  name  = "devops-team-membership"
  group = aws_iam_group.devops_team.name
  users = [for u in aws_iam_user.devops_users : u.name]
}

resource "aws_iam_user" "security_users" {
  for_each = toset(["security-engineer-1", "security-engineer-2"])
  name     = each.value
  tags     = { Lab = "lab10", Team = "security" }
}

resource "aws_iam_group_membership" "security_members" {
  name  = "security-team-membership"
  group = aws_iam_group.security_team.name
  users = [for u in aws_iam_user.security_users : u.name]
}

resource "aws_iam_user" "data_users" {
  for_each = toset(["data-engineer-1", "data-engineer-2", "data-analyst-1"])
  name     = each.value
  tags     = { Lab = "lab10", Team = "data-engineering" }
}

resource "aws_iam_group_membership" "data_eng_members" {
  name  = "data-engineering-team-membership"
  group = aws_iam_group.data_engineering_team.name
  users = [for u in aws_iam_user.data_users : u.name]
}

# Out-of-scope account admin (mirrors real environments).
resource "aws_iam_user" "platform_admin" {
  name = "platform-admin-user"
  tags = { Lab = "lab10", Team = "infrastructure", Role = "admin" }
}

resource "aws_iam_user_policy_attachment" "platform_admin_full" {
  user       = aws_iam_user.platform_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# =============================================================================
# Outputs
# =============================================================================

output "attack_chain" {
  value = [
    "Hop 1: qa-automation-engineer-3 --[iam:PutGroupPolicy]--> qa-automation-team",
    "Hop 2: new inline policy on qa-automation-team grants sts:AssumeRole on qa-platform-orchestrator-role",
    "Hop 3: qa-automation-engineer-3 --[sts:AssumeRole]--> qa-platform-orchestrator-role",
    "Hop 4: qa-platform-orchestrator-role --[iam:AttachRolePolicy AdministratorAccess]--> qa-integration-service-role",
    "Hop 5: qa-platform-orchestrator-role --[sts:AssumeRole]--> qa-integration-service-role (now AdministratorAccess attached)"
  ]
}

output "chain_entry_point" {
  value = aws_iam_user.qa_automation_engineer_3.arn
}

output "chain_final_target" {
  value = aws_iam_role.qa_integration_service_role.arn
}

output "intermediate_role" {
  value = aws_iam_role.qa_platform_orchestrator_role.arn
}

output "self_serviced_group" {
  value = aws_iam_group.qa_automation_team.arn
}

output "total_resources" {
  value = "29 users, 14 roles, 6 groups, 3 Lambda, 3 EC2, 2 S3"
}

output "cloudspider_access_key_id" {
  value       = aws_iam_access_key.qa_automation_engineer_3_key.id
  description = "Access Key ID for the chain entry-point user (qa-automation-engineer-3)"
}

output "cloudspider_secret_access_key" {
  value       = aws_iam_access_key.qa_automation_engineer_3_key.secret
  sensitive   = true
  description = "Secret Access Key — retrieve with: terraform output -raw cloudspider_secret_access_key"
}
