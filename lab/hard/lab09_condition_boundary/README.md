# Lab 09 — Condition & Boundary Evasion (Hard)

## Scenario

A security-conscious enterprise has deployed multiple defense layers: Permissions Boundaries, region-based condition restrictions, and condition-gated trust policies. However, each layer has a subtle logical flaw that allows a `restricted-dev` user to bypass all of them through a carefully constructed escalation path.

## Environment

| Category | Count | Details |
|----------|-------|---------|
| IAM Users | 10 | Across dev, ops, security, and admin teams |
| IAM Roles | 8 | Mix of bounded, conditioned, and unrestricted roles |
| IAM Groups | 3 | Team-based groups |
| EC2 Instances | 2 | Application servers |
| Lambda Functions | 1 | Data processing Lambda |
| S3 Buckets | 2 | App data, logs |

## Vulnerability — Three Layered Flaws

### Flaw 1: Permissions Boundary Bypass via AssumeRole
The `restricted-dev` user has a **Permissions Boundary** that denies `iam:*`:
```json
{
  "Effect": "Allow",
  "Action": ["s3:*", "ec2:*", "lambda:*", "logs:*", "sts:AssumeRole"],
  "Resource": "*"
}
```

The boundary allows `sts:AssumeRole`. The user's inline policy also grants `sts:AssumeRole`. So the user **can** assume roles — even roles that have NO boundary attached. Once the user assumes a role without a boundary, the boundary from the originating user no longer applies.

### Flaw 2: Region Condition That Doesn't Apply to Global Services
The `infra-deploy-role` (the role the user can assume) has an inline policy with a region condition:
```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "aws:RequestedRegion": ["us-east-1", "us-west-2"]
    }
  }
}
```

**Flaw**: `aws:RequestedRegion` restricts regional API calls, but **IAM is a global service** — IAM API calls don't populate `aws:RequestedRegion`. Because CloudSpider's evaluator uses a fail-closed strategy for unknown context keys, this condition may be evaluated differently than AWS's actual behavior where the condition is simply not evaluated for global endpoints.

### Flaw 3: Trust Policy with Org Condition Gap
The `super-admin-role` (the final target) has a trust policy gated by `aws:PrincipalOrgID`:
```json
{
  "Principal": "*",
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "aws:PrincipalOrgID": "o-exampleorgid"
    }
  }
}
```

**Flaw**: The `Principal` is `"*"` (anyone), and the condition only checks organizational membership. If the calling principal is in the organization (which all internal users/roles are), the trust policy is satisfied. Combined with Flaw 2, the `infra-deploy-role` can assume `super-admin-role`.

## Attack Chain

```
restricted-dev (has Permissions Boundary)
        │
        │  Boundary allows sts:AssumeRole
        │
        ├──[ASSUME_ROLE]──▶ infra-deploy-role (NO boundary)
        │                         │
        │              iam:* allowed because
        │              aws:RequestedRegion condition
        │              doesn't apply to global IAM calls
        │                         │
        │                  [ASSUME_ROLE]
        │                         │
        │                         ▼
        │                super-admin-role
        │               (AdministratorAccess)
        │                Trust: Principal=*
        │                Condition: PrincipalOrgID
        │                (satisfied by internal roles)
```

## CloudSpider Detection

| Capability | Detected? |
|------------|-----------|
| Permissions Boundary evaluation | ✅ Yes — boundary allows `sts:AssumeRole` |
| Boundary bypass via role chaining | ✅ Yes — assumed role has no boundary |
| Region condition on IAM calls | ⚠️ Partial — evaluator may fail-closed on missing `aws:RequestedRegion` |
| Org ID condition on trust policy | ⚠️ Partial — depends on context key availability |
| Full path discovery | ⚠️ Depends on condition evaluation behavior |

## Why Each Defense Appears Correct

| Defense Layer | Appearance | Reality |
|--------------|------------|---------|
| Permissions Boundary | Blocks `iam:*` | Allows `sts:AssumeRole`, enabling boundary escape |
| Region Condition | Restricts all actions to `us-east-1/us-west-2` | IAM is global; condition doesn't apply |
| Org ID Trust Condition | Limits assumption to org members only | All internal principals satisfy this condition |

## Difficulty: Hard
- Three independent defense layers that each appear correct
- Requires understanding of:
  - How Permissions Boundaries interact with `sts:AssumeRole` (they don't restrict role chaining)
  - That `aws:RequestedRegion` is undefined for global IAM endpoints
  - That `aws:PrincipalOrgID` is trivially satisfied by any in-account principal
- Even CloudSpider's evaluator may not fully detect this chain due to condition evaluation edge cases
- This lab intentionally pushes beyond CloudSpider's current detection capabilities as a target for future improvement
