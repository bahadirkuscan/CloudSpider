"""
Cypher query templates to enable easy expansion and updates to the search capabilities.
"""

# Shortest path between any two nodes ignoring edge types (pure connectivity)
SHORTEST_PATH_GENERAL = """
MATCH (start {arn: $start_arn}), (target {arn: $target_arn})
MATCH p=shortestPath((start)-[*1..15]->(target))
RETURN p
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
