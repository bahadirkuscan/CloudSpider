###############################################################################
# Lab 11 — Enterprise Realistic (Hard)
#
# Theme:    100-user enterprise SaaS organisation ("Acme Cloud, Inc.") with
#           19 departments, machine-identity bots, multi-account-style role
#           segmentation, and progressive tag-scoped visibility.
#
# Chain (all pure IAM-policy primitives — no Lambda/EC2/S3/secret internals):
#
#   marketing-analyst-07
#       │  iam:CreateAccessKey on marketing-data-publisher-bot
#       ▼
#   marketing-data-publisher-bot  (machine user)
#       │  iam:CreatePolicyVersion + --set-as-default
#       │     on DataOpsLifecyclePolicy (attached to the bot)
#       ▼
#   bot's effective policy now grants sts:AssumeRole on
#   glue-data-ops-job-role
#       │  sts:AssumeRole
#       ▼
#   glue-data-ops-job-role
#       │  iam:UpdateAssumeRolePolicy on roles tagged Role=break-glass
#       │  rewrites trust of break-glass-administrator-role to allow self
#       ▼
#   break-glass-administrator-role  (AdministratorAccess)
#
# Distinct attack vectors:
#   1. iam:CreateAccessKey on another user (forge fresh credentials)
#   2. iam:CreatePolicyVersion --set-as-default (policy backdoor)
#   3. sts:AssumeRole via the backdoored policy
#   4. iam:UpdateAssumeRolePolicy (trust-policy backdoor)
#   5. sts:AssumeRole to the now-trusting break-glass role
#
# Each hop unlocks broader tag-scoped discovery so the initial principal
# cannot enumerate most of the environment until they pivot deeper.
#
# Scale: 100 users + 2 machine identities, 27 IAM roles, 15 groups,
#        7 Lambda, 5 EC2, 4 S3. No secrets, no SSM, no Lambda env vars,
#        no Glue script swaps — every escalation step is a pure IAM API.
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
# Discovery policies — progressive tag-scoped visibility
# =============================================================================

resource "aws_iam_policy" "discovery_marketing_analyst" {
  name = "discovery-team-marketing-analytics"

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
          StringEquals = { "aws:ResourceTag/Team" = "marketing-analytics" }
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

  tags = { Lab = "lab11" }
}

resource "aws_iam_policy" "discovery_marketing_bot" {
  name = "discovery-marketing-data-publisher-bot"

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
        Sid    = "ReadMarketingAndDataOps"
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
            "aws:ResourceTag/Team" = ["marketing-analytics", "data-ops"]
          }
        }
      },
      {
        Sid    = "ResourceDiscovery"
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

  tags = { Lab = "lab11" }
}

resource "aws_iam_policy" "discovery_glue_role" {
  name = "discovery-glue-data-ops-role"

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
        Sid    = "ReadDataOpsAndSRE"
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
            "aws:ResourceTag/Team" = ["data-ops", "sre-platform", "infrastructure"]
          }
        }
      },
      {
        Sid    = "AlsoReadBreakGlass"
        Effect = "Allow"
        Action = [
          "iam:GetRole", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies"
        ]
        Resource = "*"
        Condition = {
          StringEquals = { "aws:ResourceTag/Role" = "break-glass" }
        }
      },
      {
        Sid    = "ResourceDiscovery"
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

  tags = { Lab = "lab11" }
}

# =============================================================================
# S3 buckets (noise — never read or written during the chain)
# =============================================================================

resource "aws_s3_bucket" "marketing_data" {
  bucket        = "acme-marketing-data-${local.account_id}"
  force_destroy = true
  tags          = { Lab = "lab11", Team = "marketing-analytics" }
}

resource "aws_s3_bucket" "data_ops_artifacts" {
  bucket        = "acme-data-ops-artifacts-${local.account_id}"
  force_destroy = true
  tags          = { Lab = "lab11", Team = "data-ops" }
}

resource "aws_s3_bucket" "build_artifacts" {
  bucket        = "acme-build-artifacts-${local.account_id}"
  force_destroy = true
  tags          = { Lab = "lab11", Team = "infrastructure" }
}

resource "aws_s3_bucket" "log_archive" {
  bucket        = "acme-log-archive-${local.account_id}"
  force_destroy = true
  tags          = { Lab = "lab11", Team = "security" }
}

# =============================================================================
# Chain Hop 1 → 2 — marketing-analyst-07 can rotate the bot's access keys
# =============================================================================

# (The IAM grant is attached to the chain entry user — see "users" section
#  below. Resource is the specific machine user's ARN.)

# =============================================================================
# Chain Hop 2 → 3 — marketing-data-publisher-bot + DataOpsLifecyclePolicy
# =============================================================================
#
# The bot is attached to DataOpsLifecyclePolicy, which it ALSO has
# iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion on. The
# justification is "data-ops lifecycle automation — the bot rolls forward
# attribution policy versions during pipeline releases". The flaw: the
# policy is attached to the bot itself, so writing a new default version
# atomically rewrites the bot's effective permissions.
# =============================================================================

resource "aws_iam_policy" "data_ops_lifecycle_policy" {
  name = "DataOpsLifecyclePolicy"

  # Initial (innocuous) version: read-only on data-ops S3.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "BaselineDataOpsRead"
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        aws_s3_bucket.data_ops_artifacts.arn,
        "${aws_s3_bucket.data_ops_artifacts.arn}/*",
        aws_s3_bucket.marketing_data.arn,
        "${aws_s3_bucket.marketing_data.arn}/*"
      ]
    }]
  })

  tags = { Lab = "lab11", Team = "data-ops", ManagedBy = "data-ops-automation" }
}

resource "aws_iam_user" "marketing_publisher_bot" {
  name = "marketing-data-publisher-bot"
  tags = { Lab = "lab11", Team = "data-ops", Type = "machine-identity" }
}

resource "aws_iam_user_policy_attachment" "marketing_publisher_bot_discovery" {
  user       = aws_iam_user.marketing_publisher_bot.name
  policy_arn = aws_iam_policy.discovery_marketing_bot.arn
}

resource "aws_iam_user_policy_attachment" "marketing_publisher_bot_lifecycle" {
  user       = aws_iam_user.marketing_publisher_bot.name
  policy_arn = aws_iam_policy.data_ops_lifecycle_policy.arn
}

# VULNERABLE: bot can write new versions of the very policy attached to it
# and atomically set the new version as default.
resource "aws_iam_user_policy" "marketing_publisher_bot_lifecycle_mgmt" {
  name = "marketing-data-publisher-bot-lifecycle-mgmt"
  user = aws_iam_user.marketing_publisher_bot.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "RollForwardLifecyclePolicy"
      Effect = "Allow"
      Action = [
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:DeletePolicyVersion",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListPolicyVersions"
      ]
      Resource = aws_iam_policy.data_ops_lifecycle_policy.arn
    }]
  })
}

# =============================================================================
# Chain Hop 3 → 4 — glue-data-ops-job-role with trust-policy backdoor power
# =============================================================================
#
# The bot's post-backdoor policy grants sts:AssumeRole on this role; the
# role's trust policy already permits any in-account principal to assume.
# Once inside, the role's IAM policy grants iam:UpdateAssumeRolePolicy on
# any role tagged Role=break-glass — the supposed "incident response"
# automation that rewrites trust during a break-glass workflow.
# =============================================================================

resource "aws_iam_role" "glue_data_ops_job_role" {
  name = "glue-data-ops-job-role"

  # Trust permits any in-account principal — typical for shared service roles.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "glue.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = { Lab = "lab11", Team = "data-ops", Description = "Trust-mutator - vulnerable" }
}

resource "aws_iam_role_policy_attachment" "glue_data_ops_managed" {
  role       = aws_iam_role.glue_data_ops_job_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role_policy_attachment" "glue_data_ops_discovery" {
  role       = aws_iam_role.glue_data_ops_job_role.name
  policy_arn = aws_iam_policy.discovery_glue_role.arn
}

# VULNERABLE: this role can rewrite trust policies of any break-glass-* role.
#
# *Justification*: the data-ops automation runbook needs to inject the
# on-call engineer's principal into the break-glass role's trust during
# pipeline-coordinated incident response. In practice the permission is
# unconditional — the role can rewrite the trust to ANY principal.
resource "aws_iam_role_policy" "glue_data_ops_trust_mutator" {
  name = "glue-data-ops-trust-mutator"
  role = aws_iam_role.glue_data_ops_job_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RewriteBreakGlassTrust"
        Effect   = "Allow"
        Action   = ["iam:UpdateAssumeRolePolicy", "iam:GetRole"]
        Resource = "arn:aws:iam::${local.account_id}:role/break-glass-*"
      },
      {
        Sid      = "AssumeBreakGlass"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::${local.account_id}:role/break-glass-*"
      },
      {
        Sid    = "OperationalBaseline"
        Effect = "Allow"
        Action = [
          "s3:GetObject", "s3:ListBucket",
          "logs:DescribeLogGroups", "logs:GetLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# Chain Hop 5 → 6 — break-glass-administrator-role (final target)
# =============================================================================
#
# Initial trust: only the (currently-unstaffed) incident-response permission
# set, gated on a PrincipalTag. The data-ops trust mutator rewrites this.
# =============================================================================

resource "aws_iam_role" "break_glass_administrator" {
  name = "break-glass-administrator-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:PrincipalTag/IncidentResponse" = "active" }
      }
    }]
  })

  tags = { Lab = "lab11", Team = "infrastructure", Role = "break-glass", Env = "production" }
}

resource "aws_iam_role_policy_attachment" "break_glass_admin_full" {
  role       = aws_iam_role.break_glass_administrator.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role" "break_glass_readonly" {
  name = "break-glass-readonly-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:PrincipalTag/IncidentResponse" = "active" }
      }
    }]
  })

  tags = { Lab = "lab11", Team = "infrastructure", Role = "break-glass", Env = "production" }
}

resource "aws_iam_role_policy_attachment" "break_glass_readonly_managed" {
  role       = aws_iam_role.break_glass_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# =============================================================================
# Noise roles (legitimate, non-vulnerable)
# =============================================================================

resource "aws_iam_role" "marketing_attribution_lambda_role" {
  name = "marketing-attribution-publisher-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "marketing-analytics" }
}

resource "aws_iam_role_policy_attachment" "marketing_attribution_logs" {
  role       = aws_iam_role.marketing_attribution_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "backend_lambda_role" {
  name = "backend-lambda-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "backend-engineering" }
}

resource "aws_iam_role_policy_attachment" "backend_lambda_basic" {
  role       = aws_iam_role.backend_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "frontend_lambda_role" {
  name = "frontend-lambda-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "frontend-engineering" }
}

resource "aws_iam_role_policy_attachment" "frontend_lambda_basic" {
  role       = aws_iam_role.frontend_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "ml_training_role" {
  name = "ml-training-job-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sagemaker.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "ml-platform" }
}

resource "aws_iam_role" "ml_inference_role" {
  name = "ml-inference-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sagemaker.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "ml-platform" }
}

resource "aws_iam_role" "crm_sync_role" {
  name = "crm-salesforce-sync-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "sales" }
}

resource "aws_iam_role" "cs_tooling_role" {
  name = "customer-success-tooling-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "customer-success" }
}

resource "aws_iam_role" "finops_reader_role" {
  name = "finops-cost-explorer-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "finance" }
}

resource "aws_iam_role" "security_ir_role" {
  name = "security-incident-response-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "security" }
}

resource "aws_iam_role" "audit_trail_role" {
  name = "audit-trail-collector-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "security" }
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
  tags = { Lab = "lab11", Team = "infrastructure" }
}

resource "aws_iam_role_policy_attachment" "ecs_task_exec_managed" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "ecs_task_backend" {
  name = "ecs-task-role-backend"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "backend-engineering" }
}

resource "aws_iam_role" "ecs_task_frontend" {
  name = "ecs-task-role-frontend"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "frontend-engineering" }
}

resource "aws_iam_role" "lambda_default_role" {
  name = "lambda-default-execution-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "infrastructure" }
}

resource "aws_iam_role_policy_attachment" "lambda_default_basic" {
  role       = aws_iam_role.lambda_default_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
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
  tags = { Lab = "lab11", Team = "infrastructure" }
}

resource "aws_iam_role" "cw_exporter_role" {
  name = "cloudwatch-exporter-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "infrastructure" }
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
  tags = { Lab = "lab11", Team = "security" }
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
  tags = { Lab = "lab11", Team = "security" }
}

resource "aws_iam_role" "cross_account_billing_role" {
  name = "cross-account-billing-readonly-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "finance" }
}

resource "aws_iam_role" "prod_deploy_role" {
  name = "prod-deployment-orchestrator-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codepipeline.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "infrastructure", Env = "production" }
}

resource "aws_iam_role" "staging_deploy_role" {
  name = "staging-deployment-orchestrator-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codepipeline.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "infrastructure", Env = "staging" }
}

resource "aws_iam_role" "mobile_app_deploy_role" {
  name = "mobile-app-deploy-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "mobile-engineering" }
}

resource "aws_iam_role" "hr_workflow_role" {
  name = "hr-workflow-automation-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Lab = "lab11", Team = "hr" }
}

# =============================================================================
# Noise Lambda functions (pure scaffolding — no env-var secrets)
# =============================================================================

data "archive_file" "dummy_lambda" {
  type        = "zip"
  output_path = "${path.module}/lambda_placeholder.zip"
  source {
    content  = "def handler(event, context):\n    return {'statusCode': 200}\n"
    filename = "index.py"
  }
}

resource "aws_lambda_function" "marketing_attribution_publisher" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "marketing-attribution-publisher"
  role             = aws_iam_role.marketing_attribution_lambda_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256
  tags             = { Lab = "lab11", Team = "marketing-analytics" }
}

resource "aws_lambda_function" "backend_health_checker" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "backend-health-checker"
  role             = aws_iam_role.backend_lambda_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256
  tags             = { Lab = "lab11", Team = "backend-engineering" }
}

resource "aws_lambda_function" "frontend_cdn_invalidator" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "frontend-cdn-invalidator"
  role             = aws_iam_role.frontend_lambda_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256
  tags             = { Lab = "lab11", Team = "frontend-engineering" }
}

resource "aws_lambda_function" "crm_salesforce_sync" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "crm-salesforce-sync"
  role             = aws_iam_role.crm_sync_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256
  tags             = { Lab = "lab11", Team = "sales" }
}

resource "aws_lambda_function" "cs_ticket_router" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "customer-success-ticket-router"
  role             = aws_iam_role.cs_tooling_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256
  tags             = { Lab = "lab11", Team = "customer-success" }
}

resource "aws_lambda_function" "audit_log_shipper" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "audit-log-shipper"
  role             = aws_iam_role.lambda_default_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256
  tags             = { Lab = "lab11", Team = "security" }
}

resource "aws_lambda_function" "billing_alert_dispatcher" {
  filename         = data.archive_file.dummy_lambda.output_path
  function_name    = "billing-alert-dispatcher"
  role             = aws_iam_role.lambda_default_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.dummy_lambda.output_base64sha256
  tags             = { Lab = "lab11", Team = "finance" }
}

# =============================================================================
# EC2 noise
# =============================================================================

resource "aws_instance" "prod_api_server_1" {
  ami           = var.ami_id
  instance_type = "t3.micro"
  tags          = { Name = "prod-api-server-01", Lab = "lab11", Team = "backend-engineering", Env = "production" }
}

resource "aws_instance" "prod_api_server_2" {
  ami           = var.ami_id
  instance_type = "t3.micro"
  tags          = { Name = "prod-api-server-02", Lab = "lab11", Team = "backend-engineering", Env = "production" }
}

resource "aws_instance" "staging_app_server" {
  ami           = var.ami_id
  instance_type = "t3.micro"
  tags          = { Name = "staging-app-server-01", Lab = "lab11", Team = "backend-engineering", Env = "staging" }
}

resource "aws_instance" "ml_training_node" {
  ami           = var.ami_id
  instance_type = "t3.micro"
  tags          = { Name = "ml-training-node-01", Lab = "lab11", Team = "ml-platform", Env = "production" }
}

resource "aws_instance" "internal_tools_host" {
  ami           = var.ami_id
  instance_type = "t3.micro"
  tags          = { Name = "internal-tools-host", Lab = "lab11", Team = "infrastructure" }
}

# =============================================================================
# Groups (15 total)
# =============================================================================

locals {
  groups = {
    "marketing-analytics-team" = {
      managed_policies = ["arn:aws:iam::aws:policy/AmazonAthenaFullAccess"]
      inline_actions   = []
    }
    "marketing-ops-team" = {
      managed_policies = []
      inline_actions   = ["cloudwatch:Get*", "cloudwatch:List*", "sns:Publish"]
    }
    "sales-team" = {
      managed_policies = []
      inline_actions   = ["dynamodb:Query", "dynamodb:GetItem"]
    }
    "customer-success-team" = {
      managed_policies = []
      inline_actions   = ["dynamodb:Query", "dynamodb:GetItem", "logs:GetLogEvents"]
    }
    "backend-engineering-team" = {
      managed_policies = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
      inline_actions   = []
    }
    "frontend-engineering-team" = {
      managed_policies = []
      inline_actions   = ["s3:GetObject", "s3:PutObject", "cloudfront:CreateInvalidation"]
    }
    "mobile-engineering-team" = {
      managed_policies = []
      inline_actions   = ["s3:GetObject", "s3:PutObject"]
    }
    "data-engineering-team" = {
      managed_policies = ["arn:aws:iam::aws:policy/AmazonAthenaFullAccess"]
      inline_actions   = ["glue:Get*", "glue:List*"]
    }
    "data-ops-team" = {
      managed_policies = []
      inline_actions   = ["glue:Get*", "glue:List*", "athena:Get*", "athena:List*"]
    }
    "data-analytics-team" = {
      managed_policies = ["arn:aws:iam::aws:policy/AmazonAthenaFullAccess"]
      inline_actions   = []
    }
    "ml-platform-team" = {
      managed_policies = ["arn:aws:iam::aws:policy/AmazonSageMakerReadOnly"]
      inline_actions   = []
    }
    "sre-platform-team" = {
      managed_policies = ["arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"]
      inline_actions   = ["ec2:Describe*", "ecs:Describe*", "ecs:List*"]
    }
    "devops-team" = {
      managed_policies = []
      inline_actions   = ["ec2:*", "ecs:*", "ecr:*", "elasticloadbalancing:*", "autoscaling:*"]
    }
    "security-team" = {
      managed_policies = ["arn:aws:iam::aws:policy/SecurityAudit"]
      inline_actions   = []
    }
    "general-readonly-team" = {
      managed_policies = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
      inline_actions   = []
    }
  }
}

resource "aws_iam_group" "groups" {
  for_each = local.groups
  name     = each.key
}

resource "aws_iam_group_policy_attachment" "group_managed_attachments" {
  for_each = {
    for pair in flatten([
      for gname, gdata in local.groups : [
        for parn in gdata.managed_policies : {
          key   = "${gname}::${parn}"
          group = gname
          arn   = parn
        }
      ]
    ]) : pair.key => pair
  }
  group      = aws_iam_group.groups[each.value.group].name
  policy_arn = each.value.arn
}

resource "aws_iam_group_policy" "group_inline_policies" {
  for_each = {
    for gname, gdata in local.groups : gname => gdata
    if length(gdata.inline_actions) > 0
  }
  name  = "${each.key}-inline"
  group = aws_iam_group.groups[each.key].name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = each.value.inline_actions
      Resource = "*"
    }]
  })
}

# =============================================================================
# Users — 100 humans + 2 machine identities + 1 admin (104 total)
# =============================================================================

locals {
  team_to_users = {
    "marketing-analytics" = [
      "marketing-analyst-01", "marketing-analyst-02", "marketing-analyst-03",
      "marketing-analyst-04", "marketing-analyst-05", "marketing-analyst-06",
      "marketing-analyst-08", "marketing-analyst-09", "marketing-analyst-10",
      "marketing-lead"
    ]
    "marketing-ops" = [
      "marketing-ops-1", "marketing-ops-2", "marketing-ops-3", "marketing-ops-4"
    ]
    "sales" = [
      "sales-rep-1", "sales-rep-2", "sales-rep-3", "sales-rep-4",
      "sales-rep-5", "sales-rep-6", "sales-rep-7", "sales-rep-8"
    ]
    "customer-success" = [
      "cs-agent-1", "cs-agent-2", "cs-agent-3", "cs-agent-4",
      "cs-agent-5", "cs-agent-6", "cs-lead", "cs-manager"
    ]
    "backend-engineering" = [
      "backend-engineer-01", "backend-engineer-02", "backend-engineer-03",
      "backend-engineer-04", "backend-engineer-05", "backend-engineer-06",
      "backend-engineer-07", "backend-engineer-08", "backend-engineer-09",
      "backend-eng-manager", "backend-eng-architect"
    ]
    "frontend-engineering" = [
      "frontend-engineer-1", "frontend-engineer-2", "frontend-engineer-3",
      "frontend-engineer-4", "frontend-engineer-5", "frontend-eng-lead"
    ]
    "mobile-engineering" = [
      "mobile-engineer-1", "mobile-engineer-2", "mobile-engineer-3", "mobile-engineer-4"
    ]
    "data-engineering" = [
      "data-engineer-1", "data-engineer-2", "data-engineer-3",
      "data-engineer-4", "data-engineer-5"
    ]
    "data-ops" = [
      "data-ops-1", "data-ops-2", "data-ops-3"
    ]
    "data-analytics" = [
      "data-analyst-1", "data-analyst-2", "data-analyst-3", "data-analyst-4"
    ]
    "ml-platform" = [
      "ml-engineer-1", "ml-engineer-2", "ml-engineer-3", "ml-engineer-4", "ml-engineer-5"
    ]
    "sre-platform" = [
      "sre-1", "sre-2", "sre-3", "sre-4", "sre-5", "sre-lead"
    ]
    "infrastructure" = [
      "devops-1", "devops-2", "devops-3", "devops-4", "devops-lead"
    ]
    "security" = [
      "security-engineer-1", "security-engineer-2",
      "security-engineer-3", "security-lead"
    ]
    "it-operations" = [
      "it-ops-1", "it-ops-2", "it-ops-3", "it-ops-4"
    ]
    "finance" = [
      "finance-analyst-1", "finance-analyst-2",
      "finance-controller", "finops-1", "cfo"
    ]
    "hr" = [
      "hr-generalist-1", "hr-generalist-2", "hr-director"
    ]
    "legal" = [
      "legal-counsel-1", "legal-counsel-2"
    ]
    "executive" = [
      "ceo", "cto", "vp-engineering"
    ]
  }

  user_to_team = merge([
    for team, users in local.team_to_users : {
      for u in users : u => team
    }
  ]...)

  team_to_group = {
    "marketing-analytics"  = "marketing-analytics-team"
    "marketing-ops"        = "marketing-ops-team"
    "sales"                = "sales-team"
    "customer-success"     = "customer-success-team"
    "backend-engineering"  = "backend-engineering-team"
    "frontend-engineering" = "frontend-engineering-team"
    "mobile-engineering"   = "mobile-engineering-team"
    "data-engineering"     = "data-engineering-team"
    "data-ops"             = "data-ops-team"
    "data-analytics"       = "data-analytics-team"
    "ml-platform"          = "ml-platform-team"
    "sre-platform"         = "sre-platform-team"
    "infrastructure"       = "devops-team"
    "security"             = "security-team"
    "it-operations"        = "general-readonly-team"
    "finance"              = "general-readonly-team"
    "hr"                   = "general-readonly-team"
    "legal"                = "general-readonly-team"
    "executive"            = "general-readonly-team"
  }
}

# CHAIN ENTRY USER — marketing-analyst-07
resource "aws_iam_user" "marketing_analyst_07" {
  name = "marketing-analyst-07"
  tags = { Lab = "lab11", Team = "marketing-analytics", Role = "chain-entry" }
}

resource "aws_iam_user_policy_attachment" "marketing_analyst_07_discovery" {
  user       = aws_iam_user.marketing_analyst_07.name
  policy_arn = aws_iam_policy.discovery_marketing_analyst.arn
}

# VULNERABLE: entry user can rotate a specific machine user's access keys.
#
# *Justification*: marketing analysts are responsible for keeping their
# team's publisher bot keys fresh — when the bot's keys expire the analyst
# rotates them via this delegated permission. Resource is locked to a
# single user ARN; looks tightly scoped.
#
# The flaw: iam:CreateAccessKey on another user produces credentials the
# caller can use directly, full-fidelity, no MFA challenge.
resource "aws_iam_user_policy" "marketing_analyst_07_key_rotation" {
  name = "marketing-analyst-07-bot-key-rotation"
  user = aws_iam_user.marketing_analyst_07.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "RotatePublisherBotKey"
      Effect = "Allow"
      Action = [
        "iam:CreateAccessKey",
        "iam:ListAccessKeys",
        "iam:UpdateAccessKey",
        "iam:DeleteAccessKey"
      ]
      Resource = aws_iam_user.marketing_publisher_bot.arn
    }]
  })
}

resource "aws_iam_access_key" "marketing_analyst_07_key" {
  user = aws_iam_user.marketing_analyst_07.name
}

# All other 100 users — loop-generated, no chain involvement
resource "aws_iam_user" "users" {
  for_each = local.user_to_team
  name     = each.key
  tags = {
    Lab  = "lab11"
    Team = each.value
  }
}

locals {
  user_to_group = {
    for u, t in local.user_to_team : u => local.team_to_group[t]
  }
  group_to_users_loop = {
    for g in distinct(values(local.team_to_group)) : g =>
    [for u, ug in local.user_to_group : u if ug == g]
  }
  group_to_users = {
    for g, users in local.group_to_users_loop :
    g => g == "marketing-analytics-team" ?
    concat(users, [aws_iam_user.marketing_analyst_07.name]) :
    users
  }
}

resource "aws_iam_group_membership" "team_memberships" {
  for_each = local.group_to_users
  name     = "${each.key}-membership"
  group    = aws_iam_group.groups[each.key].name
  users    = each.value
}

# Out-of-scope account admin (mirrors real environments).
resource "aws_iam_user" "iam_administrator" {
  name = "iam-administrator-user"
  tags = { Lab = "lab11", Team = "infrastructure", Role = "admin" }
}

resource "aws_iam_user_policy_attachment" "iam_administrator_full" {
  user       = aws_iam_user.iam_administrator.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# =============================================================================
# Outputs
# =============================================================================

output "attack_chain" {
  value = [
    "Hop 1: marketing-analyst-07 --[iam:CreateAccessKey]--> marketing-data-publisher-bot",
    "Hop 2: (use forged bot keys)",
    "Hop 3: marketing-data-publisher-bot --[iam:CreatePolicyVersion + SetDefaultPolicyVersion]--> DataOpsLifecyclePolicy (backdoor: add sts:AssumeRole on glue-data-ops-job-role)",
    "Hop 4: marketing-data-publisher-bot --[sts:AssumeRole]--> glue-data-ops-job-role",
    "Hop 5: glue-data-ops-job-role --[iam:UpdateAssumeRolePolicy]--> break-glass-administrator-role (rewrite trust to allow self)",
    "Hop 6: glue-data-ops-job-role --[sts:AssumeRole]--> break-glass-administrator-role (AdministratorAccess)"
  ]
}

output "chain_entry_point" {
  value = aws_iam_user.marketing_analyst_07.arn
}

output "chain_final_target" {
  value = aws_iam_role.break_glass_administrator.arn
}

output "intermediate_machine_user" {
  value = aws_iam_user.marketing_publisher_bot.arn
}

output "backdoorable_managed_policy" {
  value = aws_iam_policy.data_ops_lifecycle_policy.arn
}

output "trust_mutator_role" {
  value = aws_iam_role.glue_data_ops_job_role.arn
}

output "total_resources" {
  value = "100 users + 2 machine identities + 1 admin = 103 IAM users; 27 roles, 15 groups, 7 Lambda, 5 EC2, 4 S3"
}

output "total_user_count" {
  value = length(local.user_to_team) + 1 + 1 + 1
  # 100 loop users + marketing-analyst-07 + marketing-data-publisher-bot + iam-administrator-user = 103
}

output "cloudspider_access_key_id" {
  value       = aws_iam_access_key.marketing_analyst_07_key.id
  description = "Access Key ID for the chain entry-point user (marketing-analyst-07)"
}

output "cloudspider_secret_access_key" {
  value       = aws_iam_access_key.marketing_analyst_07_key.secret
  sensitive   = true
  description = "Secret Access Key — retrieve with: terraform output -raw cloudspider_secret_access_key"
}
