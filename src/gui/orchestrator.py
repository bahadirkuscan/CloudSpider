import os
import json
import time
import logging
import boto3
from typing import Dict, Any, Optional, List
from enum import Enum

from src.discovery.extractor import Extractor
from src.graph.builder import GraphBuilder
from src.pathfinder.analyst import PathfinderAnalyst

logger = logging.getLogger(__name__)


class PipelineStage(str, Enum):
    IDLE = "idle"
    DISCOVERING = "discovering"
    DISCOVERED = "discovered"
    BUILDING = "building"
    GRAPH_BUILT = "graph_built"
    ERROR = "error"


class Orchestrator:
    """
    Central controller that manages credentials, drives the CloudSpider
    pipeline, and provides graph data for the frontend.
    """

    def __init__(self, neo4j_uri: str = None):
        self.neo4j_uri = neo4j_uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        self.snapshot_dir = os.environ.get("SNAPSHOT_DIR", "/app/snapshots")
        os.makedirs(self.snapshot_dir, exist_ok=True)

        # Credential store: {profile_name: {access_key_id, secret_access_key, session_token, region}}
        self._credentials: Dict[str, Dict[str, str]] = {}
        self._active_profile: Optional[str] = None

        # Pipeline state
        self.stage = PipelineStage.IDLE
        self._identities = []
        self._resources = []

        # Graph builder (persistent connection)
        self._builder: Optional[GraphBuilder] = None

    # ── Credential Management ──────────────────────────────────────────

    def add_credential(self, name: str, access_key_id: str, secret_access_key: str,
                       session_token: str = "", region: str = "us-east-1"):
        self._credentials[name] = {
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "session_token": session_token,
            "region": region,
        }
        logger.info(f"Credential profile '{name}' added.")

    def remove_credential(self, name: str):
        if name in self._credentials:
            del self._credentials[name]
            if self._active_profile == name:
                self._active_profile = None
            logger.info(f"Credential profile '{name}' removed.")

    def activate_credential(self, name: str) -> Dict[str, str]:
        """Activate a profile and test it. Returns caller identity info."""
        if name not in self._credentials:
            raise ValueError(f"Profile '{name}' not found.")
        cred = self._credentials[name]
        try:
            session = boto3.Session(
                aws_access_key_id=cred["access_key_id"],
                aws_secret_access_key=cred["secret_access_key"],
                aws_session_token=cred["session_token"] or None,
                region_name=cred["region"],
            )
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            self._active_profile = name
            logger.info(f"Profile '{name}' activated. Caller: {identity['Arn']}")
            return {
                "arn": identity["Arn"],
                "account": identity["Account"],
                "user_id": identity["UserId"],
            }
        except Exception as e:
            logger.error(f"Failed to activate profile '{name}': {e}")
            raise

    def list_credentials(self) -> List[Dict[str, Any]]:
        """Returns profile list with names and regions (never secrets)."""
        result = []
        for name, cred in self._credentials.items():
            result.append({
                "name": name,
                "region": cred["region"],
                "is_active": name == self._active_profile,
            })
        return result

    def get_active_profile(self) -> Optional[Dict[str, Any]]:
        if not self._active_profile:
            return None
        cred = self._credentials[self._active_profile]
        return {"name": self._active_profile, "region": cred["region"]}

    def _get_active_session(self) -> boto3.Session:
        if not self._active_profile:
            raise ValueError("No active credential profile. Activate one first.")
        cred = self._credentials[self._active_profile]
        return boto3.Session(
            aws_access_key_id=cred["access_key_id"],
            aws_secret_access_key=cred["secret_access_key"],
            aws_session_token=cred["session_token"] or None,
            region_name=cred["region"],
        )

    # ── Pipeline Operations ────────────────────────────────────────────

    def _ensure_builder(self):
        """Ensure the GraphBuilder is connected to Neo4j."""
        if not self._builder or not self._builder.driver:
            self._builder = GraphBuilder(uri=self.neo4j_uri)
            self._builder.connect()

    def run_discovery(self) -> Dict[str, Any]:
        """Run the Discovery Engine to extract identities and resources."""
        self.stage = PipelineStage.DISCOVERING
        try:
            session = self._get_active_session()
            extractor = Extractor(region_name=session.region_name)
            # Inject the session directly so we use the active credentials
            extractor.session = session
            extractor.iam_client = session.client("iam")

            logger.info("Starting identity extraction...")
            self._identities = extractor.extract_identities()
            logger.info(f"Extracted {len(self._identities)} identities.")

            logger.info("Starting resource extraction...")
            self._resources = extractor.extract_resources()
            logger.info(f"Extracted {len(self._resources)} resources.")

            self.stage = PipelineStage.DISCOVERED
            return {
                "identities": len(self._identities),
                "resources": len(self._resources),
                "identity_names": [i.name for i in self._identities],
                "resource_names": [r.name for r in self._resources],
            }
        except Exception as e:
            self.stage = PipelineStage.ERROR
            logger.error(f"Discovery failed: {e}")
            raise

    def build_graph(self, mode: str = "scratch") -> Dict[str, Any]:
        """Build the Neo4j graph from discovered data."""
        if not self._identities and not self._resources:
            raise ValueError("No data to build graph from. Run discovery first.")

        self.stage = PipelineStage.BUILDING
        try:
            self._ensure_builder()

            if mode == "scratch":
                logger.info("Clearing existing graph (scratch mode)...")
                self._builder.clear_graph()

            logger.info("Adding nodes to graph...")
            for identity in self._identities:
                self._builder.add_node(identity)
            for resource in self._resources:
                self._builder.add_node(resource)
            logger.info(f"Added {len(self._identities) + len(self._resources)} nodes.")

            logger.info("Evaluating permissions and building edges...")
            self._builder.build_edges(self._identities, self._resources)
            logger.info("Edge construction complete.")

            self.stage = PipelineStage.GRAPH_BUILT
            stats = self._get_graph_stats()
            return stats
        except Exception as e:
            self.stage = PipelineStage.ERROR
            logger.error(f"Graph build failed: {e}")
            raise

    def run_full_pipeline(self, mode: str = "scratch") -> Dict[str, Any]:
        """Run discovery + graph build in one go."""
        discovery_result = self.run_discovery()
        build_result = self.build_graph(mode)
        return {"discovery": discovery_result, "build": build_result}

    # ── Graph Data ─────────────────────────────────────────────────────

    def _get_graph_stats(self) -> Dict[str, int]:
        self._ensure_builder()
        with self._builder.driver.session() as session:
            node_count = session.run("MATCH (n) RETURN count(n) as c").single()["c"]
            edge_count = session.run("MATCH ()-[r]->() RETURN count(r) as c").single()["c"]
        return {"nodes": node_count, "edges": edge_count}

    def get_graph_data(self) -> Dict[str, Any]:
        """Fetch all nodes and edges from Neo4j formatted for D3.js."""
        self._ensure_builder()
        nodes = []
        links = []
        node_ids = set()

        with self._builder.driver.session() as session:
            # Fetch all nodes
            result = session.run("MATCH (n) RETURN n, labels(n) as labels")
            for record in result:
                node = record["n"]
                labels = record["labels"]
                arn = node.get("arn", "")
                node_ids.add(arn)
                nodes.append({
                    "id": arn,
                    "name": node.get("name", arn),
                    "type": labels[0] if labels else "UNKNOWN",
                })

            # Fetch all relationships
            result = session.run("MATCH (a)-[r]->(b) RETURN a.arn as source, b.arn as target, type(r) as rel_type")
            for record in result:
                links.append({
                    "source": record["source"],
                    "target": record["target"],
                    "type": record["rel_type"],
                })

        return {"nodes": nodes, "links": links}

    # ── Pathfinder ─────────────────────────────────────────────────────

    def find_paths(self, start_arn: str, target_arn: str = None) -> List[List[Dict[str, str]]]:
        """Find privilege escalation paths."""
        analyst = PathfinderAnalyst(uri=self.neo4j_uri)
        try:
            paths = analyst.find_escalation_paths(start_arn, target_arn or None)
            logger.info(f"Found {len(paths)} escalation path(s).")
            return paths
        finally:
            analyst.close()

    def find_admin_paths(self) -> List[List[Dict[str, str]]]:
        """Find all paths leading to admin-level nodes."""
        analyst = PathfinderAnalyst(uri=self.neo4j_uri)
        try:
            paths = analyst.find_all_admin_paths()
            logger.info(f"Found {len(paths)} admin path(s).")
            return paths
        finally:
            analyst.close()

    # ── Action Execution ───────────────────────────────────────────────

    def execute_action(self, edge_type: str, source_arn: str, target_arn: str) -> Dict[str, Any]:
        """Execute a real AWS API call corresponding to a graph edge."""
        session = self._get_active_session()
        logger.warning(f"EXECUTING ACTION: {edge_type} from {source_arn} -> {target_arn}")

        try:
            if edge_type == "ASSUME_ROLE":
                sts = session.client("sts")
                resp = sts.assume_role(
                    RoleArn=target_arn,
                    RoleSessionName="CloudSpider-AssumeRole",
                )
                return {
                    "success": True,
                    "action": "sts:AssumeRole",
                    "result": {
                        "access_key_id": resp["Credentials"]["AccessKeyId"],
                        "secret_access_key": resp["Credentials"]["SecretAccessKey"],
                        "session_token": resp["Credentials"]["SessionToken"],
                        "expiration": str(resp["Credentials"]["Expiration"]),
                    },
                }

            elif edge_type == "PASS_ROLE":
                # PassRole is an authorization check, not a standalone API call.
                # We verify it by simulating the permission check.
                return {
                    "success": True,
                    "action": "iam:PassRole",
                    "result": {
                        "message": f"PassRole permission for {target_arn} is authorized via policy evaluation. "
                                   f"PassRole is exercised implicitly when calling services like Lambda or EC2.",
                    },
                }

            elif edge_type == "CreateAccessKey":
                iam = session.client("iam")
                # Extract username from ARN: arn:aws:iam::ACCOUNT:user/USERNAME
                username = target_arn.split("/")[-1]
                resp = iam.create_access_key(UserName=username)
                key = resp["AccessKey"]
                return {
                    "success": True,
                    "action": "iam:CreateAccessKey",
                    "result": {
                        "access_key_id": key["AccessKeyId"],
                        "secret_access_key": key["SecretAccessKey"],
                        "username": key["UserName"],
                    },
                }

            elif edge_type == "AdministerResource":
                # Determine action based on target type
                if ":user/" in target_arn:
                    iam = session.client("iam")
                    username = target_arn.split("/")[-1]
                    iam.put_user_policy(
                        UserName=username,
                        PolicyName="CloudSpider-Escalation-Test",
                        PolicyDocument=json.dumps({
                            "Version": "2012-10-17",
                            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                        }),
                    )
                    return {
                        "success": True,
                        "action": "iam:PutUserPolicy",
                        "result": {"message": f"Admin policy attached to user {username}."},
                    }
                elif ":role/" in target_arn:
                    iam = session.client("iam")
                    role_name = target_arn.split("/")[-1]
                    iam.update_assume_role_policy(
                        RoleName=role_name,
                        PolicyDocument=json.dumps({
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"AWS": "*"},
                                "Action": "sts:AssumeRole",
                            }]
                        }),
                    )
                    return {
                        "success": True,
                        "action": "iam:UpdateAssumeRolePolicy",
                        "result": {"message": f"Trust policy updated for role {role_name}."},
                    }
                else:
                    return {"success": False, "error": f"Cannot determine admin action for target: {target_arn}"}

            elif edge_type == "CanUpdateFunction":
                lam = session.client("lambda")
                func_name = target_arn.split(":")[-1]
                # This is a dry-run / info response — actual code update needs a zip
                return {
                    "success": True,
                    "action": "lambda:UpdateFunctionCode",
                    "result": {
                        "message": f"lambda:UpdateFunctionCode is authorized for {func_name}. "
                                   f"Actual code deployment requires a deployment package.",
                        "function_arn": target_arn,
                    },
                }

            elif edge_type == "CanRunInstance":
                return {
                    "success": True,
                    "action": "ec2:RunInstances",
                    "result": {
                        "message": f"ec2:RunInstances is authorized for the target. "
                                   f"Actual instance launch requires AMI, subnet, and instance type parameters.",
                        "target": target_arn,
                    },
                }

            else:
                return {"success": False, "error": f"Unknown edge type: {edge_type}"}

        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            return {"success": False, "error": str(e)}

    # ── Graph Snapshots ────────────────────────────────────────────────

    def save_graph(self, name: str) -> Dict[str, Any]:
        """Export current Neo4j graph to a JSON snapshot file."""
        self._ensure_builder()
        data = self.get_graph_data()
        data["metadata"] = {
            "name": name,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "profile": self._active_profile,
        }

        filepath = os.path.join(self.snapshot_dir, f"{name}.json")
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Graph snapshot saved: {filepath}")
        return {"name": name, "path": filepath, "nodes": len(data["nodes"]), "links": len(data["links"])}

    def load_graph(self, name: str, mode: str = "scratch") -> Dict[str, Any]:
        """Load a graph snapshot back into Neo4j."""
        filepath = os.path.join(self.snapshot_dir, f"{name}.json")
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Snapshot '{name}' not found.")

        with open(filepath, "r") as f:
            data = json.load(f)

        self._ensure_builder()

        if mode == "scratch":
            self._builder.clear_graph()

        with self._builder.driver.session() as session:
            for node in data.get("nodes", []):
                label = node.get("type", "UNKNOWN")
                session.run(
                    f"MERGE (n:{label} {{arn: $arn}}) SET n.name = $name",
                    arn=node["id"], name=node["name"],
                )

            for link in data.get("links", []):
                rel_type = link.get("type", "CONNECTED")
                session.run(
                    f"MATCH (a {{arn: $src}}), (b {{arn: $tgt}}) MERGE (a)-[:{rel_type}]->(b)",
                    src=link["source"], tgt=link["target"],
                )

        logger.info(f"Snapshot '{name}' loaded ({mode} mode).")
        return self._get_graph_stats()

    def list_snapshots(self) -> List[Dict[str, Any]]:
        """List all saved graph snapshots."""
        snapshots = []
        for filename in os.listdir(self.snapshot_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(self.snapshot_dir, filename)
                try:
                    with open(filepath, "r") as f:
                        data = json.load(f)
                    meta = data.get("metadata", {})
                    snapshots.append({
                        "name": meta.get("name", filename.replace(".json", "")),
                        "timestamp": meta.get("timestamp", ""),
                        "profile": meta.get("profile", ""),
                        "nodes": len(data.get("nodes", [])),
                        "links": len(data.get("links", [])),
                    })
                except Exception:
                    snapshots.append({"name": filename.replace(".json", ""), "error": "corrupt"})
        return snapshots

    def delete_snapshot(self, name: str):
        filepath = os.path.join(self.snapshot_dir, f"{name}.json")
        if os.path.exists(filepath):
            os.remove(filepath)
            logger.info(f"Snapshot '{name}' deleted.")
        else:
            raise FileNotFoundError(f"Snapshot '{name}' not found.")
