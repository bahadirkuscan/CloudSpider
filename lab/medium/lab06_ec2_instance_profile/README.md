# Lab 06 — EC2 Instance Profile Pivot (Medium)

## Scenario

A DevOps team manages infrastructure deployments. The `devops-user` has permissions to launch EC2 instances and pass IAM roles to them via instance profiles. One of the available roles — `ec2-admin-role` — has `AdministratorAccess`. By launching an EC2 instance with this role attached, the attacker can SSH into the instance and access the admin role credentials via the instance metadata service (IMDS).

## Environment

| Resource | Name | Description |
|----------|------|-------------|
| IAM User | `devops-user` | DevOps engineer — can RunInstances + PassRole (VULNERABLE) |
| IAM User | `app-developer` | Application developer (benign) |
| IAM User | `db-admin` | Database admin (benign) |
| IAM User | `network-engineer` | Network team (benign) |
| IAM Role | `ec2-admin-role` | EC2 instance profile with admin access (target) |
| IAM Role | `ec2-app-role` | EC2 instance profile with app-level access |
| IAM Role | `ec2-monitoring-role` | EC2 monitoring role |
| IAM Role | `lambda-etl-role` | Lambda ETL role (benign noise) |
| EC2 Instance | `web-server-1` | Running web server (benign) |
| EC2 Instance | `batch-worker-1` | Batch processing (benign) |
| EC2 Instance | `bastion-host` | Jump box (benign) |
| Lambda Function | `etl-processor` | ETL Lambda (benign) |

## Vulnerability

The `devops-user` has:

1. **EC2 launch permissions**:
```json
{
  "Effect": "Allow",
  "Action": ["ec2:RunInstances", "ec2:DescribeInstances", "ec2:TerminateInstances"],
  "Resource": "*"
}
```

2. **PassRole to EC2 roles** (scoped to `ec2-*` naming pattern):
```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::ACCOUNT_ID:role/ec2-*",
  "Condition": { "StringEquals": { "iam:PassedToService": "ec2.amazonaws.com" } }
}
```

The `ec2-admin-role` matches the `ec2-*` pattern and has `AdministratorAccess`.

## Attack Chain

```
devops-user ──[CanRunInstance]──▶ EC2 ──[instance profile]──▶ ec2-admin-role
devops-user ──[PASS_ROLE]──▶ ec2-admin-role
```

**Steps:**
1. Attacker compromises `devops-user` credentials.
2. Calls `ec2:RunInstances` with `--iam-instance-profile ec2-admin-role`.
3. SSHs into the new instance.
4. Calls `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-admin-role`.
5. Gets temporary admin credentials from IMDS.
6. Full administrative access achieved.

## CloudSpider Detection

| Capability | Detected? |
|------------|-----------|
| `CanRunInstance` edge from `devops-user` → EC2 | ✅ Yes |
| `PASS_ROLE` edge from `devops-user` → `ec2-admin-role` | ✅ Yes |
| Transitive path via instance profile | ✅ Yes |

## Difficulty: Medium
The PassRole permission is scoped by a condition key (`iam:PassedToService`) and a naming pattern (`ec2-*`), which appears reasonable. The vulnerability exists because the naming convention doesn't differentiate between privilege levels.
