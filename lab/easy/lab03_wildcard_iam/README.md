# Lab 03 — Wildcard IAM Actions (Easy)

## Scenario

A mid-size engineering organization with multiple teams. The `iam-manager` user was created to handle IAM provisioning tasks but was accidentally granted `iam:*` on all resources. Combined with several users, groups, and roles, this gives the IAM manager total control over the identity plane — including the ability to escalate to any privileged role or user.

## Environment

| Resource | Name | Description |
|----------|------|-------------|
| IAM User | `iam-manager` | IAM admin with `iam:*` on `*` (VULNERABLE) |
| IAM User | `backend-dev` | Backend developer |
| IAM User | `frontend-dev` | Frontend developer |
| IAM User | `qa-engineer` | QA team member |
| IAM User | `platform-admin` | Full administrator (target) |
| IAM Group | `engineering-group` | Engineering team group |
| IAM Group | `readonly-group` | Read-only access group |
| IAM Role | `cicd-role` | CI/CD pipeline execution role |
| IAM Role | `monitoring-role` | CloudWatch monitoring role |
| IAM Role | `emergency-admin-role` | Break-glass admin role |

## Vulnerability

The `iam-manager` user has:
```json
{
  "Effect": "Allow",
  "Action": "iam:*",
  "Resource": "*"
}
```

This grants **all IAM actions** on **all resources**, enabling:
- `iam:CreateAccessKey` on any user (credential theft)
- `iam:PutUserPolicy` / `iam:AttachUserPolicy` on any user (policy injection)
- `iam:UpdateAssumeRolePolicy` on any role (trust policy takeover)
- `iam:PassRole` to any role

## Attack Chains

```
iam-manager ──[CreateAccessKey]──▶ platform-admin (AdministratorAccess)
iam-manager ──[AdministerResource]──▶ platform-admin (via PutUserPolicy)
iam-manager ──[AdministerResource]──▶ emergency-admin-role (via UpdateAssumeRolePolicy)
iam-manager ──[PASS_ROLE]──▶ any role
```

## CloudSpider Detection

| Capability | Detected? |
|------------|-----------|
| `CreateAccessKey` edges to all users | ✅ Yes |
| `AdministerResource` edges (PutUserPolicy) | ✅ Yes |
| `AdministerResource` edges (UpdateAssumeRolePolicy) | ✅ Yes |
| `PASS_ROLE` edges to all roles | ✅ Yes |
| Multiple paths from `iam-manager` | ✅ Yes |

## Difficulty: Easy
While the environment has more resources (medium scale), the `iam:*` wildcard is immediately obvious in policy review. CloudSpider should produce a large number of edges from this single principal.
