import fnmatch

def match_wildcard(pattern: str, target: str, case_sensitive: bool = False) -> bool:
    """
    Matches a target string against an AWS-style wildcard pattern (* or ?).
    AWS typical ARNs are case sensitive, while IAM Actions are typically case-insensitive.
    """
    if not case_sensitive:
        pattern = pattern.lower()
        target = target.lower()
    return fnmatch.fnmatch(target, pattern)

import re

def expand_policy_variables(pattern: str, context: dict) -> str:
    """
    Expands AWS policy variables like ${aws:username} using the provided context.
    """
    if not isinstance(pattern, str):
        return pattern
        
    def replacer(match):
        key = match.group(1)
        # Often variables are case-insensitive, AWS normalizes them.
        # But for MVP, simple dict lookup.
        return str(context.get(key, ""))
        
    return re.sub(r'\$\{([^}]+)\}', replacer, pattern)
