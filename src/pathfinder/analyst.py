import logging
from collections import deque
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class PathfinderAnalyst:
    """
    Finds privilege escalation paths using BFS over in-memory graph data.
    Takes the same node/link data that the GUI visualizes — if an edge is
    visible on screen, the pathfinder will find it.
    """

    def __init__(self, graph_data: Dict[str, Any]):
        """
        Args:
            graph_data: dict with 'nodes' and 'links' lists, exactly as
                        returned by Orchestrator.get_graph_data().
        """
        self.nodes = graph_data.get("nodes", [])
        self.links = graph_data.get("links", [])

        # Build adjacency list: source_arn -> [(target_arn, rel_type), ...]
        self._adj: Dict[str, List[tuple]] = {}
        for link in self.links:
            src = link["source"]
            tgt = link["target"]
            rel = link["type"]
            self._adj.setdefault(src, []).append((tgt, rel))

        # Name lookup: arn -> friendly name
        self._names: Dict[str, str] = {n["id"]: n["name"] for n in self.nodes}

        logger.info(
            f"PathfinderAnalyst loaded: {len(self.nodes)} nodes, "
            f"{len(self.links)} edges, {len(self._adj)} sources with outgoing edges."
        )

    # ── Public API ─────────────────────────────────────────────────────

    def find_shortest_paths(self, start_arn: str, target_arn: str) -> List[List[Dict[str, str]]]:
        """
        BFS from start_arn to target_arn.  Returns all shortest paths
        (same hop-count).  Each path is a list of edge dicts with keys:
        from_arn, from_name, to_arn, to_name, relationship.
        """
        if start_arn not in self._names:
            logger.warning(f"Start node not found in graph: {start_arn}")
            return []
        if target_arn not in self._names:
            logger.warning(f"Target node not found in graph: {target_arn}")
            return []
        if start_arn == target_arn:
            logger.warning("Start and target are the same node.")
            return []

        # BFS — track ALL shortest paths (same depth)
        queue: deque = deque([(start_arn, [])])
        # For each node, record the shortest distance we've reached it at.
        # We allow re-visiting at the SAME depth to capture parallel shortest paths.
        best_dist: Dict[str, int] = {start_arn: 0}
        found: List[List[Dict[str, str]]] = []
        target_depth = None

        while queue:
            current, path = queue.popleft()
            depth = len(path)

            # If we already found the target at a shorter depth, stop
            if target_depth is not None and depth > target_depth:
                break

            if current == target_arn:
                found.append(path)
                target_depth = depth
                continue  # keep draining this depth level

            for neighbor, rel_type in self._adj.get(current, []):
                next_depth = depth + 1
                # Only visit if we haven't reached this node at a shorter distance
                if neighbor not in best_dist or best_dist[neighbor] >= next_depth:
                    best_dist[neighbor] = next_depth
                    step = {
                        "from_arn": current,
                        "from_name": self._names.get(current, current),
                        "to_arn": neighbor,
                        "to_name": self._names.get(neighbor, neighbor),
                        "relationship": rel_type,
                    }
                    queue.append((neighbor, path + [step]))

        logger.info(
            f"Pathfinder: {start_arn} -> {target_arn}: "
            f"found {len(found)} shortest path(s)"
            + (f" ({target_depth} hop(s) each)." if found else ".")
        )
        return found
