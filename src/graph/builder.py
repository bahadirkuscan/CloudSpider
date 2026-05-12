
import time
import logging
from typing import List, Union, Dict
from neo4j import GraphDatabase
import subprocess
import fnmatch

from src.models.common import Identity, Resource, NodeType
from src.evaluator.engine import PolicyEvaluator

logger = logging.getLogger(__name__)

class GraphBuilder:
    def __init__(self, uri="bolt://localhost:7687"):
        self.uri = uri
        self.driver = None
        self._container_name = "cloudspider-neo4j"

    def connect(self):
        """Connect to an already-running Neo4j instance (e.g. managed by Docker Compose)."""
        self.driver = GraphDatabase.driver(self.uri)
        max_retries = 5
        for attempt in range(max_retries):
            try:
                with self.driver.session() as session:
                    session.run("RETURN 1")
                logger.info("Successfully connected to Neo4j.")
                return
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error("Failed to connect to Neo4j after multiple retries.")
                    raise
                logger.warning(f"Neo4j not ready yet, retrying in 3 seconds... ({e})")
                time.sleep(3)

    def clear_graph(self):
        """Remove all nodes and relationships from the database."""
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
        logger.info("Graph cleared.")
        
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

    def _check_trust_policy_allows(self, identity: Identity, role: Identity) -> bool:
        """
        Check if a role's trust policy (AssumeRolePolicyDocument) allows the
        given identity to assume it.

        AWS AssumeRole requires BOTH:
          1. The caller's identity policy allows sts:AssumeRole on the role ARN
          2. The role's trust policy lists the caller (or its account root) as a
             trusted principal

        This method checks condition (2).
        Returns True if the trust policy allows the identity.
        """
        trust_doc = role.metadata.get("AssumeRolePolicyDocument", {})
        if not trust_doc:
            return False

        statements = trust_doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        account_id = self._extract_account_id(identity.id)

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            # Check Action — must include sts:AssumeRole
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            assume_action_match = any(
                fnmatch.fnmatch("sts:AssumeRole".lower(), a.lower())
                for a in actions
            )
            if not assume_action_match:
                continue

            # Check Principal
            principal = stmt.get("Principal", {})
            if principal == "*":
                return True

            if isinstance(principal, dict):
                aws_principals = principal.get("AWS", [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]

                for p in aws_principals:
                    # Exact ARN match
                    if p == identity.id:
                        return True
                    # Wildcard
                    if p == "*":
                        return True
                    # Account root principal (arn:aws:iam::ACCOUNT:root)
                    # allows any IAM identity in that account
                    if account_id and p == f"arn:aws:iam::{account_id}:root":
                        return True

                # Service principals do NOT match IAM identities
                # (e.g. {"Service": "lambda.amazonaws.com"} should NOT match a user/role)
                # If only Service principal exists, this statement doesn't apply

        return False

    def _extract_account_id(self, arn: str) -> str:
        """Extract the AWS account ID from an ARN string."""
        # ARN format: arn:aws:iam::ACCOUNT_ID:...
        # or:         arn:aws:SERVICE:REGION:ACCOUNT_ID:...
        parts = arn.split(":")
        if len(parts) >= 5:
            return parts[4]
        return ""

    def _extract_trust_services(self, role: Identity) -> list:
        """
        Extract service principals from a role's trust policy
        (AssumeRolePolicyDocument).  Returns a list of service strings
        such as ["ec2.amazonaws.com"].
        """
        trust_doc = role.metadata.get("AssumeRolePolicyDocument", {})
        if not trust_doc:
            return []

        statements = trust_doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        services = []
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if isinstance(principal, dict):
                svc = principal.get("Service", [])
                if isinstance(svc, str):
                    svc = [svc]
                services.extend(svc)
        return services

    def build_edges(self, identities: List[Identity], resources: List[Resource]):
        """
        Evaluate and build edges strictly restricted to core services: 
        S3, EC2, Lambda, RDS, IAM.
        """
        all_assets = identities + resources

        # Build lookup maps for efficient access
        identity_map: Dict[str, Identity] = {i.id: i for i in identities}
        resource_map: Dict[str, Resource] = {r.id: r for r in resources}
        group_arn_map: Dict[str, str] = {}  # group_name -> group_arn
        for i in identities:
            if i.type == NodeType.GROUP:
                group_arn_map[i.name] = i.id

        # ── MEMBER_OF edges: User → Group ──
        for identity in identities:
            if identity.type == NodeType.USER:
                user_groups = identity.metadata.get('_group_names', [])
                for gname in user_groups:
                    group_arn = group_arn_map.get(gname)
                    if group_arn:
                        self._create_edge(identity.id, group_arn, "MEMBER_OF")
                        logger.info(f"Edge: {identity.name} --[MEMBER_OF]--> {gname}")

        # ── USES_ROLE edges: Lambda → Execution Role ──
        for resource in resources:
            if resource.type == NodeType.COMPUTE and "lambda" in resource.id.lower():
                exec_role_arn = resource.metadata.get("Role", "")
                if exec_role_arn and exec_role_arn in identity_map:
                    self._create_edge(resource.id, exec_role_arn, "USES_ROLE")
                    logger.info(f"Edge: {resource.name} --[USES_ROLE]--> {identity_map[exec_role_arn].name}")

        # ── Permission-based edges ──
        for identity in identities:
            # Skip groups — groups don't directly perform actions;
            # their policies are inherited by member users
            if identity.type == NodeType.GROUP:
                continue

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
                            # Also check the role's trust policy
                            if self._check_trust_policy_allows(identity, target):
                                self._create_edge(identity.id, target.id, "ASSUME_ROLE")
                                logger.info(f"Edge: {identity.name} --[ASSUME_ROLE]--> {target.name}")
                            
                    # PassRole
                    if target_type == NodeType.ROLE:
                        # Build context with iam:PassedToService from the role's
                        # trust policy so that condition-gated PassRole policies
                        # (e.g. StringEquals iam:PassedToService = ec2.amazonaws.com)
                        # evaluate correctly.
                        passrole_ctx = {}
                        trust_services = self._extract_trust_services(target)
                        if trust_services:
                            passrole_ctx["iam:PassedToService"] = trust_services if len(trust_services) > 1 else trust_services[0]
                        if evaluator.is_allowed("iam:PassRole", target, context=passrole_ctx):
                            self._create_edge(identity.id, target.id, "PASS_ROLE")
                            logger.info(f"Edge: {identity.name} --[PASS_ROLE]--> {target.name}")

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
                            self._create_edge(identity.id, target.id, "CanUpdateFunction")
                            logger.info(f"Edge: {identity.name} --[CanUpdateFunction]--> {target.name}")
                            
                    # EC2
                    is_ec2 = "ec2" in target.id.lower() or "instance" in target.id.lower()
                    if is_ec2:
                        if evaluator.is_allowed("ec2:RunInstances", target):
                            self._create_edge(identity.id, target.id, "CanRunInstance")

                # Storage Access (S3, RDS)
                if target_type == NodeType.STORAGE:
                    is_s3 = target.id.startswith("arn:aws:s3")
                    is_rds = ":rds:" in target.id

                    if is_s3:
                        # Check read access (GetObject, ListBucket)
                        can_read = (
                            evaluator.is_allowed("s3:GetObject", target.id) or
                            evaluator.is_allowed("s3:GetObject", target.id + "/*") or
                            evaluator.is_allowed("s3:ListBucket", target)
                        )
                        # Check write access (PutObject, DeleteObject)
                        can_write = (
                            evaluator.is_allowed("s3:PutObject", target.id + "/*") or
                            evaluator.is_allowed("s3:PutObject", target.id) or
                            evaluator.is_allowed("s3:DeleteObject", target.id + "/*")
                        )
                        # Check full access (s3:*)
                        can_full = evaluator.is_allowed("s3:*", target)

                        if can_full or can_write:
                            self._create_edge(identity.id, target.id, "HAS_ACCESS")
                            logger.info(f"Edge: {identity.name} --[HAS_ACCESS]--> {target.name} (S3 write/full)")
                        elif can_read:
                            self._create_edge(identity.id, target.id, "HAS_ACCESS")
                            logger.info(f"Edge: {identity.name} --[HAS_ACCESS]--> {target.name} (S3 read)")

                    elif is_rds:
                        can_access = (
                            evaluator.is_allowed("rds:DescribeDBInstances", target) or
                            evaluator.is_allowed("rds:*", target)
                        )
                        if can_access:
                            self._create_edge(identity.id, target.id, "HAS_ACCESS")
                            logger.info(f"Edge: {identity.name} --[HAS_ACCESS]--> {target.name} (RDS)")
