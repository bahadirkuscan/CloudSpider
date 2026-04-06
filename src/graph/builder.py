
import time
import logging
from typing import List, Union
from neo4j import GraphDatabase
import subprocess

from src.models.common import Identity, Resource, NodeType
from src.evaluator.engine import PolicyEvaluator

logger = logging.getLogger(__name__)

class GraphBuilder:
    def __init__(self, uri="bolt://localhost:7687"):
        self.uri = uri
        self.driver = None
        self._container_name = "cloudspider-neo4j"
        
    def start_local_db(self):
        """Orchestrate local Neo4j Docker container start"""
        logger.info("Starting local Neo4j Docker container...")
        try:
            # Check if container exists at all and forcefully remove it to ensure a clean state
            check_all_cmd = ["docker", "ps", "-a", "-q", "-f", f"name={self._container_name}"]
            all_output = subprocess.check_output(check_all_cmd, text=True)
            if all_output.strip():
                logger.info(f"Removing old container {self._container_name} to ensure clean state...")
                subprocess.run(["docker", "rm", "-f", self._container_name], check=True)
            
            logger.info("Creating and starting new Neo4j container...")
            subprocess.run([
                "docker", "run", "-d", "--name", self._container_name, 
                "-p", "7474:7474", "-p", "7687:7687", 
                "-e", "NEO4J_AUTH=none", "neo4j:5.16"
            ], check=True)
            
            # Wait for container initialization before we try to connect
            time.sleep(10)
        except Exception as e:
            logger.error(f"Failed to manage local Neo4j Docker container: {e}")
            raise
            
        # Connect & Wait for ready
        self.driver = GraphDatabase.driver(self.uri)
        max_retries = 5
        for attempt in range(max_retries):
            try:
                with self.driver.session() as session:
                    session.run("RETURN 1")
                logger.info("Successfully connected to Neo4j.")
                break
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error("Failed to connect to Neo4j after multiple retries.")
                    raise
                logger.warning(f"Neo4j not ready yet, retrying in 5 seconds... ({e})")
                time.sleep(5)
            
    def stop_local_db(self):
        """Stop local Neo4j Docker container"""
        if self.driver:
            self.driver.close()
        try:
            subprocess.run(["docker", "stop", self._container_name], check=True)
            logger.info("Stopped local Neo4j Docker container.")
        except Exception as e:
            logger.warning(f"Could not stop container: {e}")

    def add_node(self, item: Union[Identity, Resource]):
        with self.driver.session() as session:
            label = item.type.value # USER, ROLE, COMPUTE, STORAGE, GROUP
            # Clean up properties
            name = item.name
            arn = item.id
            query = f"""
            MERGE (n:{label} {{arn: $arn}})
            SET n.name = $name
            """
            session.run(query, arn=arn, name=name)

    def _create_edge(self, source_arn: str, target_arn: str, relationship: str):
        with self.driver.session() as session:
            query = f"""
            MATCH (a {{arn: $source_arn}}), (b {{arn: $target_arn}})
            MERGE (a)-[r:{relationship}]->(b)
            """
            session.run(query, source_arn=source_arn, target_arn=target_arn)

    def build_edges(self, identities: List[Identity], resources: List[Resource]):
        """
        Evaluate and build edges strictly restricted to core services: 
        S3, EC2, Lambda, RDS, IAM.
        """
        all_assets = identities + resources
        
        for identity in identities:
            evaluator = PolicyEvaluator(identity)
            
            for target in all_assets:
                if identity.id == target.id:
                    continue # Skip self evaluation
                    
                target_type = target.type
                
                # IAM Escalations & STS
                if target_type in (NodeType.USER, NodeType.ROLE, NodeType.GROUP):
                    # AssumeRole
                    if target_type == NodeType.ROLE:
                        if evaluator.is_allowed("sts:AssumeRole", target):
                            self._create_edge(identity.id, target.id, "ASSUME_ROLE")
                            
                    # PassRole
                    if target_type == NodeType.ROLE:
                        if evaluator.is_allowed("iam:PassRole", target):
                            self._create_edge(identity.id, target.id, "PASS_ROLE")

                    # PutUserPolicy / CreateAccessKey (Target must be user)
                    if target_type == NodeType.USER:
                        if evaluator.is_allowed("iam:PutUserPolicy", target) or \
                           evaluator.is_allowed("iam:AttachUserPolicy", target):
                            self._create_edge(identity.id, target.id, "AdministerResource")
                        if evaluator.is_allowed("iam:CreateAccessKey", target):
                            self._create_edge(identity.id, target.id, "CreateAccessKey")

                    # UpdateAssumeRolePolicy (Target must be role)
                    if target_type == NodeType.ROLE:
                        if evaluator.is_allowed("iam:UpdateAssumeRolePolicy", target):
                            self._create_edge(identity.id, target.id, "AdministerResource")
                            
                # Compute Escalations (Lambda, EC2)
                if target_type == NodeType.COMPUTE:
                    # Lambda
                    is_lambda = "lambda" in target.id.lower()
                    if is_lambda:
                        if evaluator.is_allowed("lambda:UpdateFunctionCode", target) or \
                           evaluator.is_allowed("lambda:CreateFunction", target):
                            # Note: To fully execute PassRole escalate through Lambda, 
                            # we verify PassRole in Pathfinder since it requires two hops, 
                            # but we can log the action capability here.
                            self._create_edge(identity.id, target.id, "CanUpdateFunction")
                            
                    # EC2
                    is_ec2 = "ec2" in target.id.lower() or "instance" in target.id.lower()
                    if is_ec2:
                        if evaluator.is_allowed("ec2:RunInstances", target):
                            self._create_edge(identity.id, target.id, "CanRunInstance")
