from typing import List, Dict, Any
from src.evaluator.utils import match_wildcard
from src.evaluator.conditions import evaluate_condition
from src.models.common import Identity

class PolicyEvaluator:
    """
    Evaluates IAM Policies attached to an Identity to determine if a specific
    action is allowed on a target resource based on AWS evaluation rules.
    """
    
    def __init__(self, identity: Identity):
        self.identity = identity
    
    def is_allowed(self, action: str, resource_arn: str, context: Dict[str, Any] = None) -> bool:
        """
        Core evaluation engine logic.
        Validates all policies to find if an action is explicitly allowed or explicitly denied.
        Explicit Deny ALWAYS takes precedence over any Allow.
        If no Allow statement applies, returns False.
        """
        if context is None:
            context = {}
            
        allowed = False
        
        for policy in self.identity.policies:
            doc = policy.get("PolicyDocument", {})
            statements = doc.get("Statement", [])
            
            if not isinstance(statements, list):
                statements = [statements]
                
            for stmt in statements:
                effect = stmt.get("Effect", "Deny")
                
                # Check Action match
                stmt_actions = stmt.get("Action", [])
                if not isinstance(stmt_actions, list):
                    stmt_actions = [stmt_actions]
                    
                # Action matching is generally case-insensitive in AWS
                action_matches = any(match_wildcard(a, action, case_sensitive=False) for a in stmt_actions)
                
                # Note: CloudSpider ignores NotAction for the initial MVP to reduce complexity
                
                # Check Resource match
                stmt_resources = stmt.get("Resource", [])
                if not isinstance(stmt_resources, list):
                    stmt_resources = [stmt_resources]
                    
                # ARNs are generally case-sensitive
                resource_matches = any(match_wildcard(r, resource_arn, case_sensitive=True) for r in stmt_resources)
                
                # Check Conditions
                condition_block = stmt.get("Condition", {})
                condition_matches = evaluate_condition(condition_block, context)
                
                # Rule Evaluation
                if action_matches and resource_matches and condition_matches:
                    if effect == "Deny":
                        # Explicit Deny strictly overrides any other rules or subsequent statements
                        return False
                    elif effect == "Allow":
                        allowed = True
                        
        return allowed
