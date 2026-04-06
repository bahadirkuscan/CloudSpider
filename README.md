# CloudSpider

CloudSpider is a graph-based framework for automating transitive privilege escalation discovery in multi-account AWS architectures.

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
- Automates the spinning up of a local Neo4j Docker container under the hood for a frictionless backend.
- Translates Pydantic extraction models into Neo4j nodes.
- Utilizes the Policy Evaluator to determine valid privilege escalation edges (`ASSUME_ROLE`, `PASS_ROLE`, `AdministerResource`, `CanUpdateFunction`, `CanRunInstance`) across core AWS services (IAM, EC2, Lambda).

### 4. Pathfinding Analyst
Applies graph traversal algorithms via Cypher queries onto the Neo4j database to uncover transitive privilege escalation paths from low-privileged entry points to critical "Crown Jewel" assets or full administrators.

## Prerequisites
- **Python 3.8+**
- **Docker**: Must be installed and running on your host machine (CloudSpider automatically orchestrates a Neo4j container).
- **AWS CLI**: Ensure your credentials are authenticated (`aws configure`).


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
├── requirements.txt        # Python dependencies (boto3, pydantic, neo4j, etc.)
└── src/                    # Main source code directory
    ├── discovery/          # Discovery Engine: Connects to AWS
    │   └── extractor.py    # Boto3 logic for extracting Identities and Resources
    ├── evaluator/          # Logic Core: Resolves AWS IAM effective permissions
    │   ├── engine.py       # Core evaluation loop supporting Explicit Deny logic
    │   ├── utils.py        # Wildcard matching operators
    │   └── conditions.py   # Context validations like StringEquals and IfExists
    ├── graph/              # Graph Constructor: Maps environment into Neo4j
    ├── models/             # Shared Schemas: Defines the data structures
    │   └── common.py       # Pydantic models (Identity, Resource, NodeType)
    └── pathfinder/         # Analyst: Graph traversal for privilege escalation paths
```
