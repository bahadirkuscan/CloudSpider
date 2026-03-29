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
