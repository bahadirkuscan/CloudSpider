import logging
from neo4j import GraphDatabase
from typing import List, Dict, Any, Optional
from src.pathfinder import queries

logger = logging.getLogger(__name__)

class PathfinderAnalyst:
    """
    Interfaces with Neo4j to find and extract privilege escalation paths 
    using Cypher queries.
    """
    def __init__(self, uri="bolt://localhost:7687"):
        self.uri = uri
        self.driver = GraphDatabase.driver(self.uri)
        
    def close(self):
        self.driver.close()
        
    def _parse_path(self, path_obj) -> List[Dict[str, str]]:
        """Parses a Neo4j path object into a list of generic step dictionaries"""
        parsed_path = []
        for rel in path_obj.relationships:
            start_node = rel.start_node
            end_node = rel.end_node
            rel_type = type(rel).__name__
            
            parsed_path.append({
                "from_arn": start_node.get("arn", "UNKNOWN"),
                "from_name": start_node.get("name", "UNKNOWN"),
                "to_arn": end_node.get("arn", "UNKNOWN"),
                "to_name": end_node.get("name", "UNKNOWN"),
                "relationship": rel.type
            })
        return parsed_path

    def find_escalation_paths(self, start_arn: str, target_arn: Optional[str] = None) -> List[List[Dict[str, str]]]:
        """
        Finds privilege escalation paths from a starting ARN.
        If target_arn is specified, finds shortest paths directly to that target.
        """
        paths = []
        with self.driver.session() as session:
            if target_arn:
                logger.info(f"Finding path from {start_arn} to {target_arn}")
                result = session.run(queries.SHORTEST_PATH_GENERAL, start_arn=start_arn, target_arn=target_arn)
            else:
                logger.info(f"Finding all known escalation paths from {start_arn}")
                result = session.run(queries.ALL_ESCALATION_PATHS_FROM_START, start_arn=start_arn)
                
            for record in result:
                if "p" in record and record["p"] is not None:
                    paths.append(self._parse_path(record["p"]))
                    
        return paths

    def find_all_admin_paths(self) -> List[List[Dict[str, str]]]:
        """
        Finds all known paths that lead to highly privileged nodes.
        """
        paths = []
        logger.info("Finding paths to nodes with administrative reach...")
        with self.driver.session() as session:
            result = session.run(queries.ALL_ADMIN_PATHS)
            for record in result:
                if "p" in record and record["p"] is not None:
                    paths.append(self._parse_path(record["p"]))
                    
        return paths
