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
- Utilizes the Policy Evaluator to determine valid privilege escalation edges (`ASSUME_ROLE`, `PASS_ROLE`, `AdministerResource`, `CanUpdateFunction`, `CanRunInstance`) across core AWS services (IAM, EC2, Lambda).

### 4. Pathfinding Analyst
Applies graph traversal algorithms via Cypher queries onto the Neo4j database to uncover transitive privilege escalation paths from low-privileged entry points to critical "Crown Jewel" assets or full administrators.

### 5. Interactive GUI
A web-based single-page application served by Flask that provides a graphical interface to the entire pipeline.
- **Credential Manager**: Configure and switch between multiple AWS IAM credential profiles. Credentials are stored in-memory only and never persisted to disk.
- **Pipeline Controls**: Run Discovery, Build Graph (scratch or extend mode), or execute the full pipeline with a single click. Real-time log streaming via WebSocket shows live progress.
- **Graph Visualization**: Interactive D3.js force-directed graph with color-coded nodes (Users, Roles, Compute, Storage) and styled edges by relationship type. Supports drag, zoom, pan, and click interactions.
- **Pathfinder Query**: Select a start node and optionally a target to discover privilege escalation paths. Found paths are visually highlighted on the graph.
- **Action Execution**: Click any graph edge to open an action modal and execute the corresponding real AWS API call (e.g., `sts:AssumeRole`, `iam:CreateAccessKey`) with a confirmation dialog.
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
