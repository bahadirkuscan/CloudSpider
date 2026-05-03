# Lab 04 — Lambda PassRole Chain (Medium)

## Scenario

A data engineering team uses AWS Lambda for ETL pipelines. The `ci-deploy` user manages deployment of Lambda functions. Through a combination of `lambda:UpdateFunctionCode` and `iam:PassRole`, this user can inject malicious code into a Lambda function that executes with an administrative role — achieving privilege escalation through cross-service chaining.

## Environment

| Resource | Name | Description |
|----------|------|-------------|
| IAM User | `ci-deploy` | CI/CD deployment user (VULNERABLE) |
| IAM User | `data-scientist` | Data team member (benign) |
| IAM User | `ml-engineer` | ML team member (benign) |
| IAM Role | `lambda-exec-admin-role` | Lambda execution role with admin access (target) |
| IAM Role | `lambda-exec-readonly-role` | Lambda execution role with read-only access |
| IAM Role | `glue-crawler-role` | Glue service role (benign noise) |
| Lambda Function | `data-processor` | ETL Lambda function using admin exec role |
| Lambda Function | `log-aggregator` | Logging Lambda using read-only exec role |

## Vulnerability

The `ci-deploy` user has two permissions that individually appear reasonable:

1. **Lambda code deployment** — allows updating function code for deployments:
```json
{
  "Effect": "Allow",
  "Action": ["lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration"],
  "Resource": "arn:aws:lambda:*:ACCOUNT_ID:function:*"
}
```

2. **PassRole for Lambda** — allows passing roles to Lambda functions:
```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::ACCOUNT_ID:role/lambda-exec-*"
}
```

The `lambda-exec-admin-role` has `AdministratorAccess`, making it a high-value target.

## Attack Chain

```
ci-deploy ──[CanUpdateFunction]──▶ data-processor (Lambda)
ci-deploy ──[PASS_ROLE]──▶ lambda-exec-admin-role
                                        │
                              Lambda executes with admin
                              credentials via execution role
```

**Steps:**
1. Attacker compromises `ci-deploy` credentials.
2. Writes malicious Lambda code that exfiltrates the execution role's credentials from the Lambda environment variables.
3. Calls `lambda:UpdateFunctionCode` to deploy the malicious code to `data-processor`.
4. Invokes the function (or waits for scheduled trigger).
5. Retrieves the admin role's temporary credentials.
6. Full administrative access achieved.

## CloudSpider Detection

| Capability | Detected? |
|------------|-----------|
| `CanUpdateFunction` edge: `ci-deploy` → `data-processor` | ✅ Yes |
| `PASS_ROLE` edge: `ci-deploy` → `lambda-exec-admin-role` | ✅ Yes |
| Transitive path linking Lambda to its execution role | ✅ Yes (via graph traversal) |

## Difficulty: Medium
Each permission (`UpdateFunctionCode`, `PassRole`) is individually justifiable for a CI/CD user. The vulnerability only becomes apparent when both are combined — a cross-service privilege escalation chain.
