# CloudSpider

CloudSpider is a graph-based framework for automating transitive privilege escalation discovery in multi-account AWS architectures.

## Quick Start

The entire stack (Flask GUI + Neo4j database) is containerized via Docker Compose:

```bash
docker compose up -d
```

Then open **http://localhost:5000** in your browser.

## Architecture & Implementation Details

### 1. Discovery Engine
The Discovery Engine is responsible for extracting metadata from the environment using the `boto3` SDK.
- **`src.models.common`**: Defines the fundamental schemas (`Identity`, `Resource`, `NodeType`) using `pydantic`.
- **`src.discovery.extractor.Extractor`**: Implements the core extraction logic. 
  - Handles authentication and API pagination natively.
  - Extracts IAM Principals (Users, Roles).
  - Extracts core compute and storage resources (S3, EC2, Lambda, RDS) by mapping them to the common `Resource` and `Identity` models.

### 2. Policy Evaluator (Logic Core)
Parses JSON policy documents to resolve effective permissions by simulating AWS's internal evaluation algorithm.
- Supports processing inline, managed, **group-inherited**, and **resource-based** policies.
- Evaluates `Explicit Deny` overrides and default `Deny` rules with full support for `NotAction` and `NotResource`.
- Enforces strict intersection rules mapping **Permissions Boundaries**, Organization **SCPs**, and temporary **Session Policies** directly mimicking AWS evaluation behavior.
- Contains wildcard matching (`*` and `?`) and **policy variable expansion** (e.g., `${aws:username}`) for robust Action and ARN evaluation.
- Comprehensive condition block evaluation (`String`, `Numeric`, `Date`, `Bool`, `IpAddress`, `Null`, `Arn`) with `ForAnyValue` and `ForAllValues` set operators, defaulting to a **fail-closed** strategy for strict security.

### 3. Graph Constructor
Integrates with **Neo4j** to model the extracted identities, resources, and their permissions as a directed graph. 
- Managed automatically via Docker Compose — no manual container orchestration required.
- Translates Pydantic extraction models into Neo4j nodes.
- Utilizes the Policy Evaluator to determine valid privilege escalation edges across core AWS services (IAM, STS, EC2, Lambda, S3, RDS).

#### Detected Edge Types

The Graph Constructor evaluates IAM policies to discover the following edge types. Each edge represents a specific exploitable action or structural relationship.

##### Credential Access Edges (compromise target — grant direct access)

| Edge Type | AWS Action(s) | Source → Target | Prerequisites | Execution Behavior |
|---|---|---|---|---|
| `ASSUME_ROLE` | `sts:AssumeRole` | Identity → Role | Identity policy allows `sts:AssumeRole` on target role ARN **AND** the role's trust policy allows the identity as a principal. | Returns temporary STS credentials for the role. Credentials are auto-registered and activated. |
| `CreateAccessKey` | `iam:CreateAccessKey` | Identity → User | Identity policy allows `iam:CreateAccessKey` on target user ARN. | Creates a new long-term access key pair for the target user. Credentials are auto-registered. |
| `CreateLoginProfile` | `iam:CreateLoginProfile` or `iam:UpdateLoginProfile` | Identity → User | Identity policy allows either action on target user ARN. | Sets or resets the target user's console password. Returns the generated password. |

##### Policy Modification Edges (stepping stone — do NOT compromise target)

These edges modify the target's permissions but do not grant the attacker direct access. A subsequent step (e.g., `ASSUME_ROLE`) is required to leverage the modification.

| Edge Type | AWS Action(s) | Source → Target | Prerequisites | Execution Behavior |
|---|---|---|---|---|
| `PutUserPolicy` | `iam:PutUserPolicy` | Identity → User | Identity policy allows `iam:PutUserPolicy` on target user ARN. | Injects an admin inline policy (`Action: *, Resource: *`) onto the target user. |
| `AttachUserPolicy` | `iam:AttachUserPolicy` | Identity → User | Identity policy allows `iam:AttachUserPolicy` on target user ARN. | Attaches `AdministratorAccess` managed policy to the target user. |
| `PutRolePolicy` | `iam:PutRolePolicy` | Identity → Role | Identity policy allows `iam:PutRolePolicy` on target role ARN. | Injects an admin inline policy onto the target role. Assume the role to use escalated permissions. |
| `AttachRolePolicy` | `iam:AttachRolePolicy` | Identity → Role | Identity policy allows `iam:AttachRolePolicy` on target role ARN. | Attaches `AdministratorAccess` to the target role. Assume the role to use it. |
| `UpdateAssumeRolePolicy` | `iam:UpdateAssumeRolePolicy` | Identity → Role | Identity policy allows `iam:UpdateAssumeRolePolicy` on target role ARN. | Rewrites the role's trust policy to allow the current caller to assume it. |
| `PutGroupPolicy` | `iam:PutGroupPolicy` | Identity → Group | Identity policy allows `iam:PutGroupPolicy` on target group ARN. | Injects an admin inline policy onto the group. All members inherit these permissions. |
| `AttachGroupPolicy` | `iam:AttachGroupPolicy` | Identity → Group | Identity policy allows `iam:AttachGroupPolicy` on target group ARN. | Attaches `AdministratorAccess` to the group. All members inherit the policy. |
| `AddUserToGroup` | `iam:AddUserToGroup` | Identity → Group | Identity policy allows `iam:AddUserToGroup` on target group ARN. | Adds the current caller's IAM user to the target group, inheriting its policies. |
| `CreatePolicyVersion` | `iam:CreatePolicyVersion` | Identity → Self | Identity policy allows `iam:CreatePolicyVersion` on a customer-managed policy attached to itself. | Self-mutation: rewrites the managed policy with admin permissions (`Action: *, Resource: *`) and sets as default version. Handles the AWS 5-version limit. |

##### Service-Based Execution Edges

| Edge Type | AWS Action(s) | Source → Target | Prerequisites | Execution Behavior |
|---|---|---|---|---|
| `PASS_ROLE` | `iam:PassRole` | Identity → Role | Identity policy allows `iam:PassRole` on target role ARN. Conditions like `iam:PassedToService` are evaluated using the role's trust policy. | Informational: PassRole is exercised implicitly when calling services like Lambda or EC2. |
| `CanUpdateFunction` | `lambda:UpdateFunctionCode` or `lambda:CreateFunction` | Identity → Lambda | Identity policy allows either action on target Lambda ARN. | Deploys a credential-extraction payload, invokes it, harvests execution role credentials, and restores the original code. |
| `CanInvokeFunction` | `lambda:InvokeFunction` | Identity → Lambda | Identity policy allows `lambda:InvokeFunction` on target Lambda ARN. | Invokes the Lambda function with an empty payload and returns the response. |
| `CanRunInstance` | `ec2:RunInstances` | Identity → EC2 | Identity policy allows `ec2:RunInstances`. | Informational: confirms authorization. Actual launch requires AMI, subnet, and instance type parameters. |

##### Structural Edges (metadata-derived, no API call)

| Edge Type | Meaning | Source → Target | Derivation |
|---|---|---|---|
| `MEMBER_OF` | User belongs to an IAM group | User → Group | Extracted from group membership metadata during discovery. |
| `USES_ROLE` | Lambda function executes as this IAM role | Lambda → Role | Extracted from Lambda function configuration during discovery. |

##### Data Access Edges

| Edge Type | AWS Action(s) | Source → Target | Prerequisites | Execution Behavior |
|---|---|---|---|---|
| `HAS_ACCESS` | `s3:GetObject`, `s3:PutObject`, `s3:ListBucket`, `s3:*`, `rds:DescribeDBInstances`, `rds:*` | Identity → S3/RDS | Identity policy allows any read/write action on the target resource. | S3: lists bucket objects. RDS: describes the DB instance and returns endpoint info. |

### 4. Pathfinding Analyst
Applies graph traversal algorithms via Cypher queries onto the Neo4j database to uncover transitive privilege escalation paths from low-privileged entry points to critical "Crown Jewel" assets or full administrators.

### 5. Interactive GUI
A web-based single-page application served by Flask that provides a graphical interface to the entire pipeline.
- **Credential Manager**: Configure and switch between multiple AWS IAM credential profiles. Credentials are stored in-memory only and never persisted to disk.
- **Pipeline Controls**: Run Discovery, Build Graph (build or extend mode), or execute the full pipeline with a single click. Real-time log streaming via WebSocket shows live progress.
- **Graph Visualization**: Interactive D3.js force-directed graph with color-coded nodes (Users, Roles, Compute, Storage) and styled edges by relationship type. Supports drag, zoom, pan, and click interactions.
- **Pathfinder Query**: Select a start node and optionally a target to discover privilege escalation paths. Found paths are visually highlighted on the graph.
- **Action Execution**: Click any graph edge to open an action modal and execute the corresponding real AWS API call. Actions that grant direct access (e.g., `sts:AssumeRole`, `iam:CreateAccessKey`) mark the target as compromised. Stepping-stone actions (e.g., `iam:PutGroupPolicy`, `iam:AttachRolePolicy`) mark the edge as taken without compromising the target.
- **Graph Snapshots**: Save the current graph state to a JSON file and reload it later. Snapshots are persisted in a Docker volume.

## Prerequisites
- **Docker**: Must be installed and running on your host machine. Docker Compose orchestrates both the application and Neo4j containers.
- **AWS Credentials**: Access Key ID and Secret Access Key for the target AWS account(s). Credentials are configured through the GUI at runtime.

## Testing 

CloudSpider uses `pytest` and `moto` to perform fully offline unit testing, ensuring that the Boto3 extraction logic accurately parses responses without hitting real AWS infrastructure.

To run the test suite:
```bash
# From the CloudSpider root directory
python -m pytest tests/ -v
```

## Project Structure

```text
CloudSpider/
├── README.md               # Project documentation and implementation details
├── Dockerfile              # Flask application container image
├── docker-compose.yml      # Two-service stack: app (Flask) + neo4j
├── requirements.txt        # Python dependencies (boto3, pydantic, neo4j, flask, etc.)
└── src/                    # Main source code directory
    ├── discovery/          # Discovery Engine: Connects to AWS
    │   └── extractor.py    # Boto3 logic for extracting Identities and Resources
    ├── evaluator/          # Logic Core: Resolves AWS IAM effective permissions
    │   ├── engine.py       # Core evaluation loop supporting Explicit Deny logic
    │   ├── utils.py        # Wildcard matching operators
    │   └── conditions.py   # Context validations like StringEquals and IfExists
    ├── graph/              # Graph Constructor: Maps environment into Neo4j
    │   └── builder.py      # Neo4j node/edge creation and graph management
    ├── gui/                # Interactive GUI (Flask + D3.js)
    │   ├── __main__.py     # Entry point: python -m src.gui
    │   ├── app.py          # Flask REST API routes and SocketIO log streaming
    │   ├── orchestrator.py # Pipeline controller, credential store, snapshot manager
    │   └── static/         # Frontend assets
    │       ├── index.html  # Single-page application shell
    │       ├── index.css   # Dark theme design system
    │       └── app.js      # D3.js graph renderer and UI logic
    ├── models/             # Shared Schemas: Defines the data structures
    │   └── common.py       # Pydantic models (Identity, Resource, NodeType)
    └── pathfinder/         # Analyst: Graph traversal for privilege escalation paths
        ├── analyst.py      # Cypher-based path discovery
        └── queries.py      # Parameterized Cypher query templates
```
