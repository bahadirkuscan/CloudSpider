# Lab 07 — NotAction Deny Inversion (Hard)

## Scenario

A large enterprise environment uses sophisticated IAM policies with `NotAction` and `NotResource` constructs. A `support-agent` user has a policy that appears restrictive but inadvertently grants IAM and STS actions through a `NotAction` Allow statement. A companion Deny statement using `NotResource` appears to block sensitive resources but has an ARN gap that fails to protect the actual escalation target.

## Environment

| Resource | Name | Description |
|----------|------|-------------|
| **Users (12)** | `support-agent` | Support team (VULNERABLE) |
| | `support-lead`, `support-manager` | Other support staff |
| | `backend-eng-1` through `backend-eng-3` | Engineering team |
| | `data-eng-1`, `data-eng-2` | Data engineering |
| | `infra-admin` | Infrastructure admin (target) |
| | `security-ops` | Security operations |
| | `product-manager` | Product team |
| **Roles (6)** | `privileged-deploy-role` | Deployment role with admin access (target) |
| | `lambda-data-role` | Lambda execution role |
| | `lambda-api-role` | Lambda API role |
| | `glue-etl-role` | Glue service role |
| | `readonly-audit-role` | Audit trail role |
| | `cost-analysis-role` | FinOps role |
| **Groups (4)** | `support-team` | Support group |
| | `engineering-team` | Engineering group |
| | `data-team` | Data engineering group |
| | `readonly-team` | Read-only group |
| **Lambda (3)** | `api-gateway-handler` | API handler Lambda |
| | `data-ingest` | Data ingestion Lambda |
| | `alert-notifier` | Alert Lambda |
| **S3 (2)** | `company-data-lake` | Data lake bucket |
| | `deployment-artifacts` | Deployment artifacts bucket |

## Vulnerability

The `support-agent` user has a policy with two interacting statements:

### Statement 1 — NotAction Allow (the trap)
```json
{
  "Sid": "AllowNonIAMActions",
  "Effect": "Allow",
  "NotAction": [
    "organizations:*",
    "account:*"
  ],
  "Resource": "*"
}
```

**Intent**: "Allow everything except Organizations and Account management."  
**Reality**: This **allows** `iam:*` and `sts:*` because they're not in the `NotAction` exclusion list. The policy writer likely confused `NotAction` with an explicit deny.

### Statement 2 — NotResource Deny (the false guardrail)
```json
{
  "Sid": "DenySensitiveResources",
  "Effect": "Deny",
  "Action": [
    "iam:Create*", "iam:Delete*", "iam:Put*", "iam:Update*",
    "iam:Attach*", "iam:Detach*", "iam:Add*", "iam:Remove*",
    "iam:Set*", "iam:Change*", "iam:PassRole"
  ],
  "NotResource": [
    "arn:aws:iam::ACCOUNT_ID:user/support-*",
    "arn:aws:iam::ACCOUNT_ID:role/readonly-*"
  ]
}
```

**Intent**: "Deny mutating IAM actions on everything except support users and readonly roles."  
**Reality**: This denies mutating IAM actions on resources that are NOT `support-*` users or `readonly-*` roles. But `sts:AssumeRole` is NOT an `iam:` action — it's in the `sts:` namespace, so this deny doesn't cover it at all.

### The Exploit
`sts:AssumeRole` is allowed by Statement 1 (it's not `organizations:*` or `account:*`) and is **not** denied by Statement 2 (which only denies `iam:*`). The `privileged-deploy-role` trust policy allows account-wide assumption.

## Attack Chain

```
support-agent ──[ASSUME_ROLE]──▶ privileged-deploy-role (AdministratorAccess)
```

The `NotAction` Allow grants `sts:AssumeRole`, and the `NotResource` Deny only blocks `iam:*`, not `sts:*`.

## CloudSpider Detection

| Capability | Detected? |
|------------|-----------|
| `NotAction` evaluation in Allow statements | ✅ Yes |
| `sts:AssumeRole` not blocked by `iam:*` Deny | ✅ Yes |
| `ASSUME_ROLE` edge: `support-agent` → `privileged-deploy-role` | ✅ Yes |

## Difficulty: Hard
- `NotAction` in an Allow statement is counterintuitive (most engineers read it as "deny these actions")
- The Deny statement using `NotResource` **appears** to be a guardrail but operates on a different action namespace (`iam:*` vs `sts:*`)
- The interaction between the two statements requires understanding AWS's full evaluation algorithm
- Buried in a large environment with 12 users and 6 roles
