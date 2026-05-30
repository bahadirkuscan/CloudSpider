# CloudSpider

CloudSpider is a graph-based framework for automating transitive privilege escalation discovery in AWS IAM. It models an AWS environment as a directed graph — identities and resources become nodes, exploitable permissions become edges — then applies graph traversal to uncover multi-step attack paths from low-privileged entry points to administrative compromise.

## Quick Start

The entire stack (Flask GUI + Neo4j database) is containerized via Docker Compose:

```bash
docker compose up -d
```

On **first launch**, the application creates a default admin account and prints the credentials to the container logs:

```bash
docker compose logs app
```

```
============================================================
  CloudSpider — First Run Setup
============================================================
  Default admin credentials:
    Username : admin
    Password : <randomly-generated>

  ⚠  This password will NOT be shown again.
  Change it from the Admin Panel after login.
============================================================
```

Open **http://localhost:5000** in your browser, log in with the admin credentials, and change the password from the Admin Panel.

## Architecture & Implementation Details

### 1. Discovery Engine
The Discovery Engine extracts metadata from the target AWS account using the `boto3` SDK.
- **`src.models.common`**: Defines the fundamental schemas (`Identity`, `Resource`) using `pydantic`.
- **`src.discovery.extractor.Extractor`**: Implements the core extraction logic.
  - Handles authentication and API pagination natively.
  - Extracts IAM Principals (Users, Roles, Groups) with their inline policies, managed policies, group memberships, and trust policies.
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
- Translates Pydantic extraction models into Neo4j nodes with labels: `USER`, `ROLE`, `COMPUTE`, `STORAGE`, `GROUP`.
- Utilizes the Policy Evaluator to determine valid privilege escalation edges across core AWS services (IAM, STS, EC2, Lambda, S3, RDS).
- Supports **multi-user graph isolation**: each authenticated user's graph data is scoped via an `_owner` property on all Neo4j nodes, preventing cross-user data leakage within a shared database.

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
Applies BFS (Breadth-First Search) graph traversal over the in-memory graph data to uncover transitive privilege escalation paths. The pathfinder operates on the same node/link data that the GUI visualizes — if an edge is visible on screen, the pathfinder will find it. Returns **all** shortest paths (same hop-count) between a start node and a target node.

### 5. Interactive GUI
A web-based single-page application served by Flask that provides a graphical interface to the entire pipeline.
- **Login Page**: Animated network background with glassmorphism login card. Unauthenticated users are redirected here automatically.
- **Credential Manager**: Configure and switch between multiple AWS IAM credential profiles. Credentials are stored in-memory only and never persisted to disk (except within encrypted snapshots).
- **Pipeline Controls**: Run Discovery, Build Graph (build or extend mode), or execute the full pipeline with a single click. Real-time log streaming via WebSocket shows live progress.
- **Graph Visualization**: Interactive D3.js force-directed graph with color-coded nodes (Users, Roles, Compute, Storage, Groups) and styled edges by status (taken, possible, blocked, false positive). Supports drag, zoom, pan, and click interactions. Node sizing scales with degree (connection count).
- **Pathfinder Query**: Select a start node and a target to discover privilege escalation paths. Found paths are visually highlighted on the graph with cyan glow animation. Supports step-by-step or batch execution of path edges.
- **Action Execution**: Click any graph edge to open an action modal and execute the corresponding real AWS API call. Actions that grant direct access (e.g., `sts:AssumeRole`, `iam:CreateAccessKey`) auto-register the returned credentials and mark the target as compromised. Stepping-stone actions (e.g., `iam:PutGroupPolicy`, `iam:AttachRolePolicy`) mark the edge as taken without compromising the target. Edges can also be marked as false positives.
- **Graph Filtering**: Per-node and per-edge-type checkbox filters with search. Auto-filtering for large graphs (>100 edges) performs BFS from the compromised node to show only nearby nodes. Toggle to show only nodes connected by taken/possible edges.
- **Graph Snapshots**: Save the current graph state to an encrypted JSON file, including all UI state (compromised nodes, edge statuses, node positions, filter settings, credentials). Snapshots are persisted in a Docker volume. Owners can share snapshots publicly with password protection.
- **Role-Based Access**: Read-only users can view the graph and find paths but cannot execute actions, modify credentials, or save snapshots. The admin user can manage all users from the Admin Panel.

### 6. Authentication & User Management
A multi-user authentication system built on Flask-Login, SQLite, and bcrypt.
- **Three Roles**: `admin` (full access + user management), `full` (all pipeline operations), `readonly` (view-only access).
- **First-Run Setup**: On first launch, the application auto-generates a random admin password and prints it to stdout. This password is shown only once.
- **Admin Panel**: Create and delete user accounts, change user roles, change the admin password.
- **Session Isolation**: Each authenticated user gets their own Orchestrator instance with isolated credentials, pipeline state, and Neo4j graph data.
- **Snapshot Sharing**: Snapshots are private by default. Owners can make them public with a password; other users must enter the password to load a public snapshot.

## Prerequisites
- **Docker**: Must be installed and running on your host machine. Docker Compose orchestrates both the application and Neo4j containers.
- **AWS Credentials**: Access Key ID and Secret Access Key for the target AWS account. Credentials are configured through the GUI at runtime.

All Python dependencies (boto3, pydantic, neo4j, flask, flask-socketio, flask-login, bcrypt, cryptography, gevent) are bundled in the Docker image.

## Docker

The application runs as a two-service Docker Compose stack:

| Service | Image | Purpose |
|---------|-------|---------|
| `neo4j` | `neo4j:5.16` | Graph database for storing identities, resources, and privilege escalation edges |
| `app` | Built from `Dockerfile` | Flask application (Python 3.11) serving the GUI and API |

**Volumes**:
| Volume | Mount Point | Purpose |
|--------|-------------|---------|
| `graph-snapshots` | `/app/snapshots` | Encrypted graph snapshot files |
| `app-data` | `/app/data` | SQLite database (user accounts, snapshot metadata) |

The application listens on `127.0.0.1:5000` (localhost only by default).

## Testing 

CloudSpider uses `pytest` and `moto` to perform fully offline unit testing, ensuring that the Boto3 extraction logic, the IAM policy evaluation engine, and the graph construction pipeline work correctly without hitting real AWS infrastructure.

**Test files:**

| File | Tests | Coverage |
|------|-------|----------|
| `tests/test_evaluator.py` | 16 tests | Policy evaluation: Allow/Deny, wildcards, NotAction, NotResource, conditions (String, IP, set operators), group policies, resource policies, variable expansion, permissions boundaries, SCPs, session policies |
| `tests/test_extractor.py` | 5 tests | Discovery: IAM user/role extraction with inline and managed policies, S3 bucket discovery, EC2 instance discovery, Lambda function discovery (uses `moto` mock AWS) |
| `tests/test_graph.py` | 1 test | Integration: end-to-end graph construction and pathfinding with a real Neo4j instance |

To run the test suite:
```bash
# Unit tests (no external dependencies)
python -m pytest tests/test_evaluator.py tests/test_extractor.py -v

# Integration test (requires running Neo4j)
python -m pytest tests/test_graph.py -v
```

## REST API Reference

All API endpoints require authentication unless noted. Write operations require `admin` or `full` role.

| Category | Method | Endpoint | Auth | Description |
|----------|--------|----------|------|-------------|
| **Auth** | `POST` | `/api/auth/login` | None | Authenticate with username/password |
| | `POST` | `/api/auth/logout` | Required | End the current session |
| | `GET` | `/api/auth/me` | Required | Get current user info |
| **Admin** | `GET` | `/api/admin/users` | Admin | List all user accounts |
| | `POST` | `/api/admin/users` | Admin | Create a new user account |
| | `DELETE` | `/api/admin/users/<username>` | Admin | Delete user and their data |
| | `PUT` | `/api/admin/users/<username>/role` | Admin | Change a user's role |
| | `PUT` | `/api/admin/password` | Admin | Change admin password |
| **Credentials** | `GET` | `/api/credentials` | Required | List credential profiles |
| | `POST` | `/api/credentials` | Write | Add a new credential profile |
| | `DELETE` | `/api/credentials/<name>` | Write | Remove a credential profile |
| | `POST` | `/api/credentials/<name>/activate` | Write | Activate a profile (calls STS) |
| | `GET` | `/api/credentials/active` | Required | Get active profile info |
| **Pipeline** | `POST` | `/api/pipeline/discover` | Write | Run the Discovery Engine |
| | `POST` | `/api/pipeline/build` | Write | Build the Neo4j graph |
| | `POST` | `/api/pipeline/run-all` | Write | Discover + Build in one step |
| | `GET` | `/api/pipeline/status` | Required | Get current pipeline stage |
| **Graph** | `GET` | `/api/graph` | Required | Fetch all nodes and edges |
| | `DELETE` | `/api/graph` | Write | Clear the graph |
| **Pathfinder** | `POST` | `/api/pathfinder/query` | Required | Find escalation paths |
| **Actions** | `POST` | `/api/action/execute` | Write | Execute a real AWS API action |
| **Snapshots** | `GET` | `/api/snapshots` | Required | List own + public snapshots |
| | `POST` | `/api/snapshots/save` | Write | Save encrypted snapshot |
| | `POST` | `/api/snapshots/load` | Required | Load a snapshot |
| | `DELETE` | `/api/snapshots/<name>` | Required | Delete a snapshot |
| | `POST` | `/api/snapshots/<name>/visibility` | Write | Toggle public/private |
| **Session** | `GET` | `/api/session/state` | Required | Get persisted UI state |
| | `POST` | `/api/session/state` | Required | Save UI state |
| | `DELETE` | `/api/session/state` | Required | Clear UI state |

**WebSocket Events** (via Socket.IO):
- `log` — Real-time log streaming: `{level, message, logger, timestamp}`
- `pipeline_status` — Pipeline stage transitions: `{stage, message}`

## Project Structure

```text
CloudSpider/
├── README.md               # Project documentation and implementation details
├── Dockerfile              # Flask application container image (Python 3.11)
├── docker-compose.yml      # Two-service stack: app (Flask) + neo4j
├── requirements.txt        # Python dependencies
├── lab/                    # Vulnerable Terraform labs for testing (see lab/README.md)
├── tests/                  # Test suite
│   ├── test_evaluator.py   # Policy evaluation unit tests (16 tests)
│   ├── test_extractor.py   # Discovery extraction unit tests (5 tests, moto)
│   └── test_graph.py       # Graph + pathfinder integration test
└── src/                    # Main source code directory
    ├── discovery/          # Discovery Engine: Connects to AWS
    │   └── extractor.py    # Boto3 logic for extracting Identities and Resources
    ├── evaluator/          # Logic Core: Resolves AWS IAM effective permissions
    │   ├── __init__.py
    │   ├── engine.py       # Core evaluation loop (6-zone AWS IAM simulation)
    │   ├── utils.py        # Wildcard matching operators
    │   └── conditions.py   # Condition block evaluation (12+ operators)
    ├── graph/              # Graph Constructor: Maps environment into Neo4j
    │   ├── __init__.py
    │   └── builder.py      # Neo4j node/edge creation and graph management
    ├── gui/                # Interactive GUI (Flask + D3.js)
    │   ├── __init__.py
    │   ├── __main__.py     # Entry point: python -m src.gui
    │   ├── app.py          # Flask REST API routes, Flask-Login auth, SocketIO
    │   ├── db.py           # SQLite database layer (users, snapshot metadata)
    │   ├── orchestrator.py # Pipeline controller, credential store, action execution,
    │   │                   # encrypted snapshot management, session isolation
    │   └── static/         # Frontend assets
    │       ├── index.html  # Single-page application shell
    │       ├── index.css   # Dark theme design system (Inter + JetBrains Mono)
    │       ├── app.js      # D3.js graph renderer, pathfinder UI, action modals
    │       ├── login.html  # Authentication login page
    │       └── login.css   # Login page styling
    ├── models/             # Shared Schemas: Defines the data structures
    │   └── common.py       # Pydantic models (Identity, Resource)
    └── pathfinder/         # Analyst: Graph traversal for privilege escalation paths
        ├── __init__.py
        ├── analyst.py      # BFS-based shortest path discovery
        └── queries.py      # Parameterized Cypher query templates
```
