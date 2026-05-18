"""
Cypher query templates to enable easy expansion and updates to the search capabilities.
"""

# ── All traversable edge types for pathfinding ──
# Used as a shared reference for the relationship type filters in Cypher queries.
# Structural:  MEMBER_OF, USES_ROLE
# Credential:  ASSUME_ROLE, CreateAccessKey, CreateLoginProfile
# Policy Mod:  PutUserPolicy, AttachUserPolicy, PutRolePolicy, AttachRolePolicy,
#              PutGroupPolicy, AttachGroupPolicy, UpdateAssumeRolePolicy,
#              CreatePolicyVersion, AddUserToGroup
# Service:     PASS_ROLE, CanUpdateFunction, CanInvokeFunction, CanRunInstance
# Data:        HAS_ACCESS
_ALL_EDGE_TYPES = (
    "ASSUME_ROLE|CreateAccessKey|CreateLoginProfile|"
    "PutUserPolicy|AttachUserPolicy|PutRolePolicy|AttachRolePolicy|"
    "PutGroupPolicy|AttachGroupPolicy|UpdateAssumeRolePolicy|"
    "CreatePolicyVersion|AddUserToGroup|"
    "PASS_ROLE|CanUpdateFunction|CanInvokeFunction|CanRunInstance|"
    "MEMBER_OF|USES_ROLE|HAS_ACCESS"
)

# Shortest path between any two nodes ignoring edge types (pure connectivity).
# Uses a single MATCH clause with shortestPath — this is critical for Neo4j 5.x
# query planner compatibility. Two separate MATCH clauses cause the planner to
# silently return zero results.
SHORTEST_PATH_GENERAL = """
MATCH p = shortestPath((start {arn: $start_arn})-[*1..15]->(target {arn: $target_arn}))
RETURN p
"""

# Fallback: variable-length path search (no shortestPath function).
# Returns paths ordered by length so shortest comes first.
VARIABLE_LENGTH_PATH = """
MATCH p = (start {arn: $start_arn})-[*1..15]->(target {arn: $target_arn})
RETURN p
ORDER BY length(p)
LIMIT 10
"""

# Debug: verify that both nodes exist in the graph
DEBUG_NODE_EXISTS = """
OPTIONAL MATCH (s {arn: $start_arn})
OPTIONAL MATCH (t {arn: $target_arn})
RETURN s IS NOT NULL AS start_exists, t IS NOT NULL AS target_exists
"""

# Find paths specifically leading to nodes that are highly privileged
ALL_ADMIN_PATHS = f"""
MATCH (n)
WHERE (n)<-[:ASSUME_ROLE|PutUserPolicy|AttachUserPolicy|PutRolePolicy|AttachRolePolicy|PutGroupPolicy|AttachGroupPolicy|UpdateAssumeRolePolicy|CreatePolicyVersion|CreateAccessKey|CreateLoginProfile]-()
WITH n
MATCH p=(start)-[:{_ALL_EDGE_TYPES}*1..10]->(n)
WHERE start <> n
RETURN p, n
"""

# Find escalation paths from a starting node to any node
ALL_ESCALATION_PATHS_FROM_START = f"""
MATCH p=(start {{arn: $start_arn}})-[:{_ALL_EDGE_TYPES}*1..10]->(target)
WHERE start <> target AND size(nodes(p)) > 1
RETURN p
"""

