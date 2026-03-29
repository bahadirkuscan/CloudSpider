import fnmatch
from typing import Dict, Any, List

def evaluate_condition(condition_block: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """
    Evaluates an AWS IAM condition block against a given evaluation context.
    Returns True if all conditions evaluate to True. Default is True if no conditions exist.
    """
    if not condition_block:
        return True
    
    # AWS Condition logic requires ALL condition operator categories to match.
    for operator, key_value_pairs in condition_block.items():
        op = operator.lower()
        
        # Determine behavior based on IfExists suffix
        if_exists = False
        if op.endswith("ifexists"):
            if_exists = True
            op = op.replace("ifexists", "")
            
        for key, expected_values in key_value_pairs.items():
            context_val = context.get(key)
            
            # If the context key is missing:
            # - If it's an "IfExists" check, it evaluates to True.
            # - Otherwise, it evaluates to False.
            if context_val is None:
                if if_exists:
                    continue
                return False
                
            if not isinstance(expected_values, list):
                expected_values = [expected_values]
                
            # Perform evaluation logic depending on the operator
            if op == "stringequals":
                if str(context_val) not in [str(v) for v in expected_values]:
                    return False
            elif op == "stringnotequals":
                if str(context_val) in [str(v) for v in expected_values]:
                    return False
            elif op == "stringequalsignorecase":
                if str(context_val).lower() not in [str(v).lower() for v in expected_values]:
                    return False
            elif op == "stringlike":
                matched = any(fnmatch.fnmatch(str(context_val), str(v)) for v in expected_values)
                if not matched:
                    return False
            elif op == "stringnotlike":
                matched = any(fnmatch.fnmatch(str(context_val), str(v)) for v in expected_values)
                if matched:
                    return False
            elif op == "arnlike" or op == "arneasquals":
                # ARN conditionals often function exactly like string matching against ARNs
                matched = any(fnmatch.fnmatch(str(context_val), str(v)) for v in expected_values)
                if not matched:
                    return False
            # For this MVP, ignore unhandled conditions by treating them as pass
            # To be fully secure, unhandled operators in Deny can pass, but unhandled in Allow shouldn't?
            # Default to true for any unsupported operator (e.g. Bool, Date) until implemented.

    return True
