# Lab 02 — Direct AssumeRole (Easy)

## Scenario

A data analytics team environment where an `analyst` user has been granted `sts:AssumeRole` with a wildcard resource pattern. This allows the analyst to assume **any** role in the account — including the `full-admin-role` which has `AdministratorAccess`.

## Environment

| Resource | Name | Description |
|----------|------|-------------|
| IAM User | `analyst` | Data analyst with read-only base permissions |
| IAM User | `finance-viewer` | Finance team read-only user (benign) |
| IAM Role | `full-admin-role` | Full administrator role |
| IAM Role | `data-pipeline-role` | Legitimate data pipeline role (benign noise) |

## Vulnerability

The `analyst` user has an inline policy with:
```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "*"
}
```

The `full-admin-role` trust policy allows any principal in the account to assume it:
```json
{
  "Principal": { "AWS": "arn:aws:iam::ACCOUNT_ID:root" },
  "Action": "sts:AssumeRole"
}
```

## Attack Chain

```
analyst ──[ASSUME_ROLE]──▶ full-admin-role (AdministratorAccess)
```

**Steps:**
1. Attacker compromises `analyst` credentials.
2. Enumerates roles via `aws iam list-roles`.
3. Calls `aws sts assume-role --role-arn <full-admin-role-arn>`.
4. Uses temporary credentials — full administrative access.

## CloudSpider Detection

| Capability | Detected? |
|------------|-----------|
| `ASSUME_ROLE` edge from `analyst` → `full-admin-role` | ✅ Yes |
| Path: `analyst` → `full-admin-role` | ✅ Yes |

## Difficulty: Easy
Wildcard `sts:AssumeRole` on `Resource: *` is a classic over-permission. The trust policy is wide-open to the account root.
