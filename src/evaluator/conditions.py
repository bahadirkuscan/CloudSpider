import fnmatch
from typing import Dict, Any, List
import ipaddress
import datetime

def _ensure_list(val):
    if not isinstance(val, list):
        return [val]
    return val

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
        
        if_exists = False
        if op.endswith("ifexists"):
            if_exists = True
            op = op.replace("ifexists", "")
            
        for_all = False
        for_any = False
        if op.startswith("forallvalues:"):
            for_all = True
            op = op.replace("forallvalues:", "")
        elif op.startswith("foranyvalue:"):
            for_any = True
            op = op.replace("foranyvalue:", "")
            
        for key, expected_values in key_value_pairs.items():
            context_vals = context.get(key)
            
            if context_vals is None:
                if if_exists: continue
                if op == "null":
                    expected_bool = str(expected_values).lower() == 'true'
                    if expected_bool: # Key is expected to be absent
                        continue
                    else:
                        return False # expected absent=False but it is missing
                return False
                
            context_vals_list = _ensure_list(context_vals)
            expected_values_list = _ensure_list(expected_values)
            
            if for_all:
                for c_val in context_vals_list:
                    if not _eval_single_condition(op, c_val, expected_values_list): return False
            elif for_any:
                if not any(_eval_single_condition(op, c_val, expected_values_list) for c_val in context_vals_list):
                    return False
            else:
                for c_val in context_vals_list:
                    if not _eval_single_condition(op, c_val, expected_values_list): return False

    return True

def _eval_single_condition(op: str, context_val: Any, expected_values: List[Any]) -> bool:
    if op == "stringequals":
        return str(context_val) in [str(v) for v in expected_values]
    elif op == "stringnotequals":
        return str(context_val) not in [str(v) for v in expected_values]
    elif op == "stringequalsignorecase":
        return str(context_val).lower() in [str(v).lower() for v in expected_values]
    elif op == "stringnotequalsignorecase":
        return str(context_val).lower() not in [str(v).lower() for v in expected_values]
    elif op == "stringlike":
        return any(fnmatch.fnmatch(str(context_val), str(v)) for v in expected_values)
    elif op == "stringnotlike":
        return not any(fnmatch.fnmatch(str(context_val), str(v)) for v in expected_values)
    elif op == "arnlike" or op == "arnequals":
        return any(fnmatch.fnmatch(str(context_val), str(v)) for v in expected_values)
    elif op == "arnnotlike" or op == "arnnotequals":
        return not any(fnmatch.fnmatch(str(context_val), str(v)) for v in expected_values)
    elif op.startswith("numeric"):
        try:
            c_num = float(context_val)
            for v in expected_values:
                v_num = float(v)
                if op == "numericequals" and c_num == v_num: return True
                if op == "numericnotequals" and c_num != v_num: return True
                if op == "numericlessthan" and c_num < v_num: return True
                if op == "numericlessthanequals" and c_num <= v_num: return True
                if op == "numericgreaterthan" and c_num > v_num: return True
                if op == "numericgreaterthanequals" and c_num >= v_num: return True
            return False
        except ValueError:
            return False
    elif op == "bool":
        c_bool = str(context_val).lower() == "true"
        return any((str(v).lower() == "true") == c_bool for v in expected_values)
    elif op == "null":
        c_missing = context_val is None or context_val == ""
        return any((str(v).lower() == "true") == c_missing for v in expected_values)
    elif op == "binaryequals":
        return str(context_val) in [str(v) for v in expected_values]
    elif op.startswith("ipaddress"):
        try:
            c_ip = ipaddress.ip_address(str(context_val))
            for v in expected_values:
                v_net = ipaddress.ip_network(str(v))
                if op == "ipaddress" and c_ip in v_net: return True
                if op == "notipaddress" and c_ip not in v_net: return True
            return False
        except ValueError:
            return False
    elif op.startswith("date"):
        try:
            def parse_date(d):
                if isinstance(d, (int, float)) or (isinstance(d, str) and d.replace(".","").isdigit()):
                    return datetime.datetime.fromtimestamp(float(d), datetime.timezone.utc)
                d_str = str(d).replace('Z', '+00:00')
                return datetime.datetime.fromisoformat(d_str)
                
            c_date = parse_date(context_val)
            for v in expected_values:
                v_date = parse_date(v)
                if op == "dateequals" and c_date == v_date: return True
                if op == "datenotequals" and c_date != v_date: return True
                if op == "datelessthan" and c_date < v_date: return True
                if op == "datelessthanequals" and c_date <= v_date: return True
                if op == "dategreaterthan" and c_date > v_date: return True
                if op == "dategreaterthanequals" and c_date >= v_date: return True
            return False
        except Exception:
            return False

    # Fail closed for unhandled operator types
    return False
