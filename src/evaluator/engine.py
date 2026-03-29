from typing import List, Dict, Any, Union, Optional, Tuple
from src.evaluator.utils import match_wildcard, expand_policy_variables
from src.evaluator.conditions import evaluate_condition
from src.models.common import Identity, Resource

class PolicyEvaluator:
    """
    Evaluates IAM Policies attached to an Identity to determine if a specific
    action is allowed on a target resource based on AWS evaluation rules.
    """
    
    def __init__(self, identity: Identity):
        self.identity = identity
    
    def _eval_policy_set(self, policies: List[Dict[str, Any]], action: str, resource_arn: str, context: Dict[str, Any], is_resource_policy: bool) -> Tuple[bool, bool]:
        """
        Evaluates a set of policies and returns (has_allow, has_deny).
        """
        has_allow = False
        for policy in policies:
            if not policy:
                continue
            doc = policy.get("PolicyDocument", {})
            statements = doc.get("Statement", [])
            
            if not isinstance(statements, list):
                statements = [statements]
                
            for stmt in statements:
                effect = stmt.get("Effect", "Deny")
                
                # Check Principal (for resource policies)
                if is_resource_policy:
                    principal_match = False
                    if "Principal" in stmt:
                        principal = stmt.get("Principal")
                        if principal == "*":
                            principal_match = True
                        elif isinstance(principal, dict) and "AWS" in principal:
                            aws_principals = principal["AWS"]
                            if not isinstance(aws_principals, list):
                                aws_principals = [aws_principals]
                            if self.identity.id in aws_principals or "*" in aws_principals:
                                principal_match = True
                    elif "NotPrincipal" in stmt:
                        principal = stmt.get("NotPrincipal")
                        principal_match = True
                        if isinstance(principal, dict) and "AWS" in principal:
                            aws_principals = principal["AWS"]
                            if not isinstance(aws_principals, list):
                                aws_principals = [aws_principals]
                            if self.identity.id in aws_principals:
                                principal_match = False
                    
                    if not principal_match:
                        continue
                
                # Check Action match
                action_matches = False
                if "Action" in stmt:
                    stmt_actions = stmt["Action"]
                    if not isinstance(stmt_actions, list): stmt_actions = [stmt_actions]
                    action_matches = any(match_wildcard(expand_policy_variables(a, context), action, False) for a in stmt_actions)
                elif "NotAction" in stmt:
                    stmt_nactions = stmt["NotAction"]
                    if not isinstance(stmt_nactions, list): stmt_nactions = [stmt_nactions]
                    action_matches = not any(match_wildcard(expand_policy_variables(a, context), action, False) for a in stmt_nactions)
                
                if not action_matches:
                    continue
                
                # Check Resource match
                resource_matches = False
                if "Resource" in stmt:
                    stmt_resources = stmt["Resource"]
                    if not isinstance(stmt_resources, list): stmt_resources = [stmt_resources]
                    resource_matches = any(match_wildcard(expand_policy_variables(r, context), resource_arn, True) for r in stmt_resources)
                elif "NotResource" in stmt:
                    stmt_nresources = stmt["NotResource"]
                    if not isinstance(stmt_nresources, list): stmt_nresources = [stmt_nresources]
                    resource_matches = not any(match_wildcard(expand_policy_variables(r, context), resource_arn, True) for r in stmt_nresources)
                else:
                    if is_resource_policy:
                        resource_matches = True
                
                if not resource_matches:
                    continue
                
                # Check Conditions
                condition_block = stmt.get("Condition", {})
                condition_matches = evaluate_condition(condition_block, context)
                
                # Rule Evaluation
                if condition_matches:
                    if effect == "Deny":
                        # Explicit Deny strictly overrides any other rules or subsequent statements
                        return False, True
                    elif effect == "Allow":
                        has_allow = True
                        
        return has_allow, False
    
    def is_allowed(self, action: str, resource: Union[str, "Resource"], context: Optional[Dict[str, Any]] = None, session_policies: Optional[List[Dict[str, Any]]] = None) -> bool:
        """
        Core evaluation engine logic.
        Validates the intersection of Base Policies, Permissions Boundaries, SCPs, and Session Policies.
        """
        if context is None:
            context = {}
            
        resource_arn = resource.id if isinstance(resource, Resource) else resource
        
        # 1. Base Zone Evaluation
        base_policies = self.identity.policies + getattr(self.identity, "group_policies", [])
        base_allow, base_deny = self._eval_policy_set(base_policies, action, resource_arn, context, False)
        if base_deny:
            return False
            
        if isinstance(resource, Resource) and hasattr(resource, "policies") and resource.policies:
            res_allow, res_deny = self._eval_policy_set(resource.policies, action, resource_arn, context, True)
            if res_deny:
                return False
            base_allow = base_allow or res_allow
            
        if not base_allow:
            return False
            
        # 2. Permissions Boundary Zone
        pb = getattr(self.identity, "permissions_boundary", None)
        if pb:
            pb_allow, pb_deny = self._eval_policy_set([pb], action, resource_arn, context, False)
            if pb_deny or not pb_allow:
                return False
                
        # 3. SCP Zone
        scps = getattr(self.identity, "scps", [])
        if scps:
            scp_allow, scp_deny = self._eval_policy_set(scps, action, resource_arn, context, False)
            if scp_deny or not scp_allow:
                return False
                
        # 4. Session Policies Zone
        if session_policies:
            sp_allow, sp_deny = self._eval_policy_set(session_policies, action, resource_arn, context, False)
            if sp_deny or not sp_allow:
                return False
                
        return True
