# Lab 01 — Overprivileged User (Easy)

## Scenario

A small startup environment with two IAM users. The `dev-user` developer account has been granted `iam:CreateAccessKey` permissions scoped broadly enough to target the `admin-user` account. This allows the developer to generate new access keys for the administrator, effectively gaining full administrative access.

## Environment

| Resource | Name | Description |
|----------|------|-------------|
| IAM User | `admin-user` | Full administrator with `AdministratorAccess` |
| IAM User | `dev-user` | Developer with inline policy granting `iam:CreateAccessKey` on all users |
| IAM Role | `deploy-role` | Deployment role (benign noise) |

## Vulnerability

The `dev-user` has an inline policy with:
```json
{
  "Effect": "Allow",
  "Action": "iam:CreateAccessKey",
  "Resource": "arn:aws:iam::*:user/*"
}
```

This allows `dev-user` to create access keys for **any** IAM user in the account — including `admin-user`.

## Attack Chain

```
dev-user ──[CreateAccessKey]──▶ admin-user (AdministratorAccess)
```

**Steps:**
1. Attacker compromises `dev-user` credentials.
2. Calls `aws iam create-access-key --user-name admin-user`.
3. Uses the returned access key to authenticate as `admin-user`.
4. Full administrative access achieved.

## CloudSpider Detection

| Capability | Detected? |
|------------|-----------|
| `CreateAccessKey` edge from `dev-user` → `admin-user` | ✅ Yes |
| Path: `dev-user` → `admin-user` | ✅ Yes |

## Difficulty: Easy
The misconfiguration is a single overly broad inline policy statement with a clear `Resource: *` pattern.
