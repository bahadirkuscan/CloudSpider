import pytest
from src.evaluator.engine import PolicyEvaluator
from src.models.common import Identity, NodeType, Resource

def create_identity(policies) -> Identity:
    return Identity(
        id="arn:aws:iam::123456789012:user/testuser",
        name="testuser",
        type=NodeType.USER,
        policies=policies,
        metadata={}
    )

def test_explicit_allow():
    policies = [{
        "PolicyName": "AllowS3",
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::mybucket/*"
                }
            ]
        }
    }]
    evaluator = PolicyEvaluator(create_identity(policies))
    assert evaluator.is_allowed("s3:GetObject", "arn:aws:s3:::mybucket/resource") is True
    assert evaluator.is_allowed("s3:PutObject", "arn:aws:s3:::mybucket/resource") is False

def test_explicit_deny_overrides_allow():
    policies = [{
        "PolicyName": "AllowAllS3",
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteBucket",
                    "Resource": "*"
                }
            ]
        }
    }]
    evaluator = PolicyEvaluator(create_identity(policies))
    assert evaluator.is_allowed("s3:GetObject", "arn:aws:s3:::mybucket") is True
    assert evaluator.is_allowed("s3:DeleteBucket", "arn:aws:s3:::mybucket") is False

def test_wildcard_matching():
    policies = [{
        "PolicyName": "Wildcards",
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:Get*", "s3:List*"],
                    "Resource": "arn:aws:s3:::foo*"
                }
            ]
        }
    }]
    evaluator = PolicyEvaluator(create_identity(policies))
    assert evaluator.is_allowed("s3:GetObject", "arn:aws:s3:::foobar") is True
    assert evaluator.is_allowed("s3:PutObject", "arn:aws:s3:::foobar") is False
    assert evaluator.is_allowed("s3:GetObject", "arn:aws:s3:::barfoo") is False

def test_conditions_string_equals():
    policies = [{
        "PolicyName": "ConditionStringEq",
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ec2:StartInstances",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:username": "johndoe"
                        }
                    }
                }
            ]
        }
    }]
    evaluator = PolicyEvaluator(create_identity(policies))
    assert evaluator.is_allowed("ec2:StartInstances", "arn:aws:ec2:...", context={"aws:username": "johndoe"}) is True
    assert evaluator.is_allowed("ec2:StartInstances", "arn:aws:ec2:...", context={"aws:username": "janedoe"}) is False
    assert evaluator.is_allowed("ec2:StartInstances", "arn:aws:ec2:...", context={}) is False

def test_conditions_if_exists():
    policies = [{
        "PolicyName": "ConditionIfExists",
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {
                        "StringEqualsIfExists": {
                            "sourceip": "10.0.0.1"
                        }
                    }
                }
            ]
        }
    }]
    evaluator = PolicyEvaluator(create_identity(policies))
    assert evaluator.is_allowed("s3:GetObject", "*", context={"sourceip": "10.0.0.1"}) is True
    assert evaluator.is_allowed("s3:GetObject", "*", context={"sourceip": "10.0.0.2"}) is False
    assert evaluator.is_allowed("s3:GetObject", "*", context={}) is True # Key doesn't exist, IfExists passes!

def test_mixed_policies():
    policies = [
        {"PolicyDocument": {
            "Statement": [
                {"Effect": "Allow", "Action": "lambda:*", "Resource": "*"}
            ]
        }},
        {"PolicyDocument": {
            "Statement": [
                {"Effect": "Deny", "Action": "lambda:DeleteFunction", "Resource": "arn:aws:lambda:*:*:function:prod-*"}
            ]
        }}
    ]
    evaluator = PolicyEvaluator(create_identity(policies))
    assert evaluator.is_allowed("lambda:InvokeFunction", "arn:aws:lambda:us-east-1:123:function:prod-auth") is True
    assert evaluator.is_allowed("lambda:DeleteFunction", "arn:aws:lambda:us-east-1:123:function:dev-auth") is True
    assert evaluator.is_allowed("lambda:DeleteFunction", "arn:aws:lambda:us-east-1:123:function:prod-auth") is False

def test_not_action():
    policies = [{
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotAction": "s3:DeleteBucket",
                    "Resource": "arn:aws:s3:::mybucket"
                }
            ]
        }
    }]
    evaluator = PolicyEvaluator(create_identity(policies))
    assert evaluator.is_allowed("s3:GetObject", "arn:aws:s3:::mybucket") is True
    assert evaluator.is_allowed("s3:DeleteBucket", "arn:aws:s3:::mybucket") is False

def test_not_resource():
    policies = [{
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "NotResource": "arn:aws:s3:::mybucket/secret"
                }
            ]
        }
    }]
    evaluator = PolicyEvaluator(create_identity(policies))
    assert evaluator.is_allowed("s3:GetObject", "arn:aws:s3:::mybucket/public") is True
    assert evaluator.is_allowed("s3:GetObject", "arn:aws:s3:::mybucket/secret") is False

def test_group_policies():
    identity = create_identity([])
    identity.group_policies = [{
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::mybucket"
                }
            ]
        }
    }]
    evaluator = PolicyEvaluator(identity)
    assert evaluator.is_allowed("s3:GetObject", "arn:aws:s3:::mybucket") is True
    assert evaluator.is_allowed("s3:PutObject", "arn:aws:s3:::mybucket") is False

def test_resource_policy():
    identity = create_identity([])
    bucket = Resource(
        id="arn:aws:s3:::mybucket",
        name="mybucket",
        type=NodeType.STORAGE,
        policies=[{
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:user/testuser"},
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::mybucket"
                    }
                ]
            }
        }]
    )
    evaluator = PolicyEvaluator(identity)
    assert evaluator.is_allowed("s3:GetObject", bucket) is True
    assert evaluator.is_allowed("s3:PutObject", bucket) is False

def test_policy_variable_expansion():
    policies = [{
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::mybucket/home/${aws:username}/*"
                }
            ]
        }
    }]
    evaluator = PolicyEvaluator(create_identity(policies))
    assert evaluator.is_allowed("s3:GetObject", "arn:aws:s3:::mybucket/home/johndoe/file.txt", context={"aws:username": "johndoe"}) is True
    assert evaluator.is_allowed("s3:GetObject", "arn:aws:s3:::mybucket/home/janedoe/file.txt", context={"aws:username": "johndoe"}) is False

def test_condition_ipaddress():
    policies = [{
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": "192.168.1.0/24"
                        }
                    }
                }
            ]
        }
    }]
    evaluator = PolicyEvaluator(create_identity(policies))
    assert evaluator.is_allowed("s3:GetObject", "arn:aws:s3:::mybucket", context={"aws:SourceIp": "192.168.1.15"}) is True
    assert evaluator.is_allowed("s3:GetObject", "arn:aws:s3:::mybucket", context={"aws:SourceIp": "10.0.0.5"}) is False

def test_condition_forallvalues():
    policies = [{
        "PolicyDocument": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                    "Condition": {
                        "ForAllValues:StringEquals": {
                            "aws:TagKeys": ["project", "cost-center"]
                        }
                    }
                }
            ]
        }
    }]
    evaluator = PolicyEvaluator(create_identity(policies))
    # True if the user only specifies tag keys "project" and "cost-center"
    assert evaluator.is_allowed("iam:PassRole", "*", context={"aws:TagKeys": ["project"]}) is True
    assert evaluator.is_allowed("iam:PassRole", "*", context={"aws:TagKeys": ["project", "cost-center"]}) is True
    # False if the user includes a tag key not in the allowed list
    assert evaluator.is_allowed("iam:PassRole", "*", context={"aws:TagKeys": ["project", "environment"]}) is False

