# CloudSpider — Vulnerable Terraform Labs

A collection of intentionally vulnerable AWS IAM environments for testing and validating CloudSpider's privilege escalation detection capabilities. Each lab is a self-contained Terraform configuration that deploys a realistic (but vulnerable) IAM topology.

> **⚠️ WARNING**: These labs deploy intentionally insecure IAM configurations. **Never deploy to production accounts.** Use a dedicated sandbox AWS account and destroy resources immediately after testing.

## Lab Categories

| Difficulty | Labs | Focus |
|:-----------|:-----|:------|
| **Easy** | 01 – 03 | Direct, single-hop privilege escalation. Misconfigurations are obvious upon policy inspection. |
| **Medium** | 04 – 06 | Multi-hop transitive chains, cross-service pivoting (Lambda/EC2), and group-inherited permissions. |
| **Hard** | 07 – 09 | `NotAction`/`NotResource` inversions, deeply buried chains in large environments, permissions boundary bypasses, and condition block evasion. |

## Lab Index

### Easy
| # | Name | Scale | Vulnerability | CloudSpider Detection |
|---|------|-------|---------------|----------------------|
| 01 | [Overprivileged User](easy/lab01_overprivileged_user/) | Small (2 users, 1 role) | `iam:CreateAccessKey` on admin user | ✅ `CreateAccessKey` edge |
| 02 | [Direct AssumeRole](easy/lab02_direct_assume_role/) | Small (2 users, 2 roles) | `sts:AssumeRole *` to admin role | ✅ `ASSUME_ROLE` edge |
| 03 | [Wildcard IAM](easy/lab03_wildcard_iam/) | Medium (5 users, 3 roles, 2 groups) | `iam:*` on all resources | ✅ Multiple admin edges |

### Medium
| # | Name | Scale | Vulnerability | CloudSpider Detection |
|---|------|-------|---------------|----------------------|
| 04 | [Lambda PassRole Chain](medium/lab04_lambda_passrole/) | Medium (3 users, 3 roles, 2 Lambdas) | UpdateFunctionCode + PassRole to admin Lambda role | ✅ `CanUpdateFunction` + `PASS_ROLE` |
| 05 | [Group Inherited Escalation](medium/lab05_group_inherited/) | Medium (8 users, 3 groups, 4 roles) | Group inline policy grants AssumeRole to admin role | ✅ Group policy evaluation |
| 06 | [EC2 Instance Profile Pivot](medium/lab06_ec2_instance_profile/) | Medium (4 users, 4 roles, 3 EC2s, 1 Lambda) | RunInstances + PassRole to admin instance profile | ✅ `CanRunInstance` + `PASS_ROLE` |

### Hard
| # | Name | Scale | Vulnerability | CloudSpider Detection |
|---|------|-------|---------------|----------------------|
| 07 | [NotAction Deny Inversion](hard/lab07_notaction_inversion/) | Large (12 users, 6 roles, 4 groups, 3 Lambdas, 2 S3) | `NotAction` Allow inadvertently grants IAM actions | ✅ `NotAction`/`NotResource` eval |
| 08 | [Deep Transitive Chain](hard/lab08_deep_transitive/) | Large (15 users, 10 roles, 5 groups, 3 EC2s, 2 Lambdas, 2 S3, 1 RDS) | 5+ hop buried chain through noise | ✅ Transitive Cypher pathfinding |
| 09 | [Condition & Boundary Evasion](hard/lab09_condition_boundary/) | Large (10 users, 8 roles, 3 groups, 2 EC2, 1 Lambda, 2 S3) | Boundary bypass + region condition gap + trust policy flaw | ⚠️ Partial |

## Usage

Each lab provisions **IAM access keys** for the entry-point (attacker) user and a **discovery policy** granting read-only permissions that CloudSpider's extractor needs to enumerate the environment. After `terraform apply`, you get credentials ready to plug into CloudSpider.

```bash
# 1. Deploy the lab
cd lab/easy/lab01_overprivileged_user
terraform init
terraform apply

# 2. Retrieve the initial credentials
terraform output cloudspider_access_key_id
terraform output -raw cloudspider_secret_access_key

# 3. Configure CloudSpider with these credentials via the GUI Credential Manager
#    (http://localhost:5000 → Credentials → Add Profile)

# 4. Run the full pipeline: Discovery → Build Graph → Pathfinder
#    CloudSpider will discover the environment, build the graph, and find attack paths.

# 5. Exploit: Click on a discovered edge to execute the action (e.g., sts:AssumeRole)

# Destroy after testing
terraform destroy
```

## Lab Design Principles

1. **Realistic naming**: All resources use plausible enterprise naming conventions to simulate real environments.
2. **Variable scale**: Small labs isolate a single vulnerability; large labs bury vulnerabilities in operational noise.
3. **Progressive difficulty**: Easy labs have obvious policy misconfigurations; Hard labs require understanding of AWS evaluation logic edge cases.
4. **Beyond CloudSpider**: Some labs include vulnerabilities that CloudSpider may not currently detect, serving as roadmap targets for future detection capabilities.
