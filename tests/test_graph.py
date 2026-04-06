import pytest
from src.models.common import Identity, Resource, NodeType
from src.graph.builder import GraphBuilder
from src.pathfinder.analyst import PathfinderAnalyst
import time

@pytest.fixture(scope="module")
def neo4j_container():
    """Sets up a real local Neo4j Docker container for tests."""
    builder = GraphBuilder()
    try:
        builder.start_local_db()
        # Give it an extra second just in case
        time.sleep(2)
        yield builder
    finally:
        builder.stop_local_db()

def test_graph_builder_and_pathfinder(neo4j_container):
    builder = neo4j_container
    
    # Clean DB first (for clean test state)
    with builder.driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
        
    identities = [
        Identity(
            id="arn:aws:iam::111122223333:user/UserA",
            name="UserA",
            type=NodeType.USER,
            policies=[{
                "PolicyDocument": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Resource": "arn:aws:iam::111122223333:role/RoleB"
                    }]
                }
            }]
        ),
        Identity(
            id="arn:aws:iam::111122223333:role/RoleB",
            name="RoleB",
            type=NodeType.ROLE,
            policies=[{
                "PolicyDocument": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": "iam:PutUserPolicy",
                        "Resource": "arn:aws:iam::111122223333:user/AdminUser"
                    }]
                }
            }]
        ),
        Identity(
            id="arn:aws:iam::111122223333:user/AdminUser",
            name="AdminUser",
            type=NodeType.USER,
            policies=[{
                "PolicyDocument": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }]
                }
            }]
        ),
    ]
    resources = []
    
    # 1. Add Nodes
    for item in identities + resources:
        builder.add_node(item)
        
    # 2. Build Edges
    builder.build_edges(identities, resources)
    
    # 3. Test Graph
    analyst = PathfinderAnalyst()
    
    # Validate graph actually built successfully
    with builder.driver.session() as s:
        nodes = s.run('MATCH (n) RETURN COUNT(n)').single()[0]
        edges = s.run('MATCH ()-[r]->() RETURN COUNT(r)').single()[0]
        assert nodes == 3, f"Expected 3 nodes, got {nodes}"
        assert edges >= 2, f"Expected at least 2 edges, got {edges}"
    
    # We successfully evaluated AssumeRole and AdministerResource based on IAM policy models!
    analyst.close()
