# Lab 08 — Deep Transitive Chain (Hard)

## Scenario

A large enterprise with 15+ users, 10 roles, multiple groups, and various compute and storage resources. A privilege escalation chain spanning 5+ hops is buried deep within the environment. Each individual permission along the chain appears legitimate and properly scoped — the vulnerability only becomes visible through graph traversal connecting all the hops together.

## Environment

| Category | Count | Details |
|----------|-------|---------|
| IAM Users | 15 | Across analytics, engineering, data, ops, and security teams |
| IAM Roles | 10 | Mix of service roles, cross-account roles, and deployment roles |
| IAM Groups | 5 | Team-based groups with various permissions |
| EC2 Instances | 3 | Web server, batch worker, analytics node |
| Lambda Functions | 2 | ETL processor, event handler |
| S3 Buckets | 2 | Data lake, artifact store |
| RDS Instances | 1 | Analytics database |

## Vulnerability — The 5-Hop Chain

Each hop is individually justifiable:

### Hop 1: `junior-analyst` → `analytics-support-group`
The `junior-analyst` is a member of `analytics-support-group`, which has a group policy allowing `sts:AssumeRole` on `data-reader-role`. *Justification: analysts need read access to data sources.*

### Hop 2: `data-reader-role` → `sts:AssumeRole` + `iam:PassRole` → `etl-execution-role`
The `data-reader-role` can assume and pass the `etl-execution-*` roles. *Justification: data readers trigger ETL jobs directly and need to assume the ETL execution role.*

### Hop 3: `etl-execution-role` → `lambda:UpdateFunctionCode` → `etl-processor` Lambda
The `etl-execution-role` can update Lambda function code. *Justification: ETL pipeline deploys updated transformation logic.*

### Hop 4: `etl-processor` Lambda → executes as `lambda-admin-exec-role`
The `etl-processor` Lambda's execution role is `lambda-admin-exec-role`, which has broad permissions. *Justification: ETL needs access to multiple data stores and services.*

### Hop 5: `lambda-admin-exec-role` → `sts:AssumeRole` → `infrastructure-admin-role`
The `lambda-admin-exec-role` can assume `infrastructure-admin-role`. *Justification: cross-account infrastructure management for ETL pipeline deployment.*

## Attack Chain (Full Path)

```
junior-analyst
    │
    ├──[member of]──▶ analytics-support-group
    │                       │
    │              [group policy: AssumeRole]
    │                       │
    ▼                       ▼
data-reader-role ──[ASSUME_ROLE + PASS_ROLE]──▶ etl-execution-role
                                        │
                               [CanUpdateFunction]
                                        │
                                        ▼
                                etl-processor (Lambda)
                                        │
                               [execution role]
                                        │
                                        ▼
                             lambda-admin-exec-role
                                        │
                                  [ASSUME_ROLE]
                                        │
                                        ▼
                            infrastructure-admin-role
                               (AdministratorAccess)
```

## Why Each Hop Looks Benign

| Hop | Permission | Justification |
|-----|-----------|---------------|
| 1 | Group AssumeRole to `data-reader-role` | Analysts need data access |
| 2 | `data-reader-role` AssumeRole + PassRole to `etl-execution-*` | Data readers run ETL pipelines |
| 3 | `etl-execution-role` UpdateFunctionCode | ETL pipeline deployments |
| 4 | Lambda exec role = `lambda-admin-exec-role` | ETL needs broad data access |
| 5 | `lambda-admin-exec-role` AssumeRole to `infrastructure-admin-role` | Cross-system management |

## CloudSpider Detection

| Capability | Detected? |
|------------|-----------|
| Group-inherited AssumeRole (Hop 1) | ✅ Yes |
| PASS_ROLE edge (Hop 2) | ✅ Yes |
| CanUpdateFunction edge (Hop 3) | ✅ Yes |
| Transitive path traversal (all 5 hops) | ✅ Yes (up to 15 hops) |
| Noise filtering (14 other users, 9 other roles) | ✅ Graph highlights the path |

## Difficulty: Hard
- 5+ hops means manual policy review cannot discover this chain
- Each permission is individually justified with a legitimate business reason
- The chain traverses IAM → IAM → Lambda → IAM → IAM (cross-service boundaries)
- Large environment creates significant noise that obscures the path
- Only automated graph traversal can reliably discover this chain
