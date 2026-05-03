# Lab 05 — Group Inherited Escalation (Medium)

## Scenario

A company uses IAM groups to manage permissions at scale. The `readonly-support-group` was intended to provide read-only access, but a misconfigured inline group policy also grants `sts:AssumeRole` to the `ops-admin-role`. Any member of this group — including the `intern` user — inherits this privilege escalation path, even though their individual user policies show nothing suspicious.

## Environment

| Resource | Name | Description |
|----------|------|-------------|
| IAM User | `intern` | Intern user, member of readonly-support-group (VULNERABLE via group) |
| IAM User | `l1-support` | L1 support, member of readonly-support-group |
| IAM User | `l2-support` | L2 support, member of readonly-support-group |
| IAM User | `sre-lead` | SRE lead, member of sre-group |
| IAM User | `sre-oncall` | SRE on-call, member of sre-group |
| IAM User | `security-auditor` | Security team (benign) |
| IAM User | `platform-owner` | Platform owner (benign, admin) |
| IAM User | `billing-admin` | Billing admin (benign) |
| IAM Group | `readonly-support-group` | Support team group — has hidden AssumeRole (VULNERABLE) |
| IAM Group | `sre-group` | SRE team group |
| IAM Group | `admin-group` | Admin group |
| IAM Role | `ops-admin-role` | Operations admin role (target) |
| IAM Role | `cloudwatch-role` | Monitoring role (benign) |
| IAM Role | `config-role` | AWS Config role (benign) |
| IAM Role | `backup-role` | Backup role (benign) |

## Vulnerability

The `readonly-support-group` has an inline group policy with:
```json
{
  "Statement": [
    {
      "Sid": "SupportReadOnly",
      "Effect": "Allow",
      "Action": ["support:*", "trustedadvisor:*"],
      "Resource": "*"
    },
    {
      "Sid": "AssumeOpsRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::ACCOUNT_ID:role/ops-admin-role"
    }
  ]
}
```

The second statement is buried among legitimate support permissions. All group members inherit this, but it's invisible when inspecting individual user policies.

## Attack Chain

```
intern ──[member of]──▶ readonly-support-group ──[group policy: AssumeRole]──▶ ops-admin-role
```

**Steps:**
1. Attacker compromises `intern` credentials.
2. Individual user policies show nothing interesting (no inline, no managed policies).
3. Group membership reveals `readonly-support-group`.
4. Group inline policy contains `sts:AssumeRole` to `ops-admin-role`.
5. Calls `aws sts assume-role --role-arn <ops-admin-role-arn>`.
6. Gains operations administrator access.

## CloudSpider Detection

| Capability | Detected? |
|------------|-----------|
| Group-inherited policy evaluation | ✅ Yes |
| `ASSUME_ROLE` edge from `intern` → `ops-admin-role` | ✅ Yes |
| Same edge from `l1-support`, `l2-support` | ✅ Yes |

## Difficulty: Medium
The vulnerability is hidden within a group policy. Inspecting individual user policies reveals nothing. Attackers (and auditors) must trace group memberships to discover the escalation path.
