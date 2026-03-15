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
*(Pending Implementation)*
Parses JSON policy documents to resolve effective permissions by simulating AWS's internal evaluation algorithm, accounting for `Explicit Deny`, `Allow`, and conditional logic blocks.

### 3. Graph Constructor
*(Pending Implementation)*
Integrates with **Neo4j** to model the extracted identities, resources, and their permissions as a directed graph. Nodes represent assets, and edges represent potential actions or trust relationships (e.g., `AssumeRole`).

### 4. Pathfinding Analyst
*(Pending Implementation)*
Applies graph traversal algorithms (like Breadth-First Search or Dijkstra's) via Cypher queries onto the Neo4j database to uncover transitive privilege escalation paths from low-privileged entry points to critical "Crown Jewel" assets.

## Getting Started

1. Set up your Python environment and install dependencies:
```bash
pip install -r requirements.txt
```
2. Configure your AWS credentials via `aws configure`.
3. The project source is structured under `src/`.

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
    ├── graph/              # Graph Constructor: Maps environment into Neo4j
    ├── models/             # Shared Schemas: Defines the data structures
    │   └── common.py       # Pydantic models (Identity, Resource, NodeType)
    └── pathfinder/         # Analyst: Graph traversal for privilege escalation paths
```
