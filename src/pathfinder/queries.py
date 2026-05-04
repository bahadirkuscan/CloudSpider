"""
Cypher query templates to enable easy expansion and updates to the search capabilities.
"""

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

# Find paths specifically leading to nodes that are highly privileged (e.g., have AdministerResource rights over a lot of things)
ALL_ADMIN_PATHS = """
MATCH (n)
WHERE (n)<-[:ASSUME_ROLE|AdministerResource|CreateAccessKey]-()
WITH n
MATCH p=(start)-[:ASSUME_ROLE|AdministerResource|CreateAccessKey|PASS_ROLE|CanUpdateFunction|CanRunInstance*1..10]->(n)
WHERE start <> n
RETURN p, n
"""

# Find escalation paths from a starting node to any node
ALL_ESCALATION_PATHS_FROM_START = """
MATCH p=(start {arn: $start_arn})-[:ASSUME_ROLE|AdministerResource|CreateAccessKey|PASS_ROLE|CanUpdateFunction|CanRunInstance*1..10]->(target)
WHERE start <> target AND size(nodes(p)) > 1
RETURN p
"""
