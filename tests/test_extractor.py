import pytest
import boto3
from moto import mock_aws
from src.discovery.extractor import Extractor
from src.models.common import NodeType

@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    import os
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

@pytest.fixture
def extractor(aws_credentials):
    with mock_aws():
        ext = Extractor(region_name="us-east-1")
        ext.authenticate()
        yield ext

def test_extract_users(extractor):
    iam_client = boto3.client("iam", region_name="us-east-1")
    iam_client.create_user(UserName="test-user-1")
    iam_client.create_user(UserName="test-user-2")
    
    identities = extractor.extract_identities()
    
    users = [i for i in identities if i.type == NodeType.USER]
    assert len(users) == 2
    user_names = [u.name for u in users]
    assert "test-user-1" in user_names
    assert "test-user-2" in user_names

def test_extract_roles(extractor):
    iam_client = boto3.client("iam", region_name="us-east-1")
    assume_role_policy_document = '{"Statement": [{"Action": "sts:AssumeRole", "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}}]}'
    iam_client.create_role(RoleName="test-role-1", AssumeRolePolicyDocument=assume_role_policy_document)
    
    identities = extractor.extract_identities()
    
    roles = [i for i in identities if i.type == NodeType.ROLE]
    assert len(roles) == 1
    assert roles[0].name == "test-role-1"

def test_extract_s3_buckets(extractor):
    s3_client = boto3.client("s3", region_name="us-east-1")
    s3_client.create_bucket(Bucket="test-bucket-1")
    s3_client.create_bucket(Bucket="test-bucket-2")
    
    resources = extractor.extract_resources()
    
    buckets = [r for r in resources if r.type == NodeType.STORAGE and r.id.startswith("arn:aws:s3:::")]
    assert len(buckets) == 2
    bucket_names = [b.name for b in buckets]
    assert "test-bucket-1" in bucket_names
    assert "test-bucket-2" in bucket_names

def test_extract_ec2_instances(extractor):
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    # Moto requires an AMI for EC2 instances. Using a mocked one.
    instances = ec2_client.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    instance_id = instances["Instances"][0]["InstanceId"]
    
    resources = extractor.extract_resources()
    
    compute_resources = [r for r in resources if r.type == NodeType.COMPUTE and r.id.startswith("arn:aws:ec2:")]
    assert len(compute_resources) == 1
    assert compute_resources[0].name == instance_id # Since no tags were added, name defaults to instance_id

def test_extract_lambda_functions(extractor):
    lambda_client = boto3.client("lambda", region_name="us-east-1")
    iam_client = boto3.client("iam", region_name="us-east-1")
    assume_role_policy_document = '{"Statement": [{"Action": "sts:AssumeRole", "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}}]}'
    role = iam_client.create_role(RoleName="lambda-role", AssumeRolePolicyDocument=assume_role_policy_document)
    
    # Needs a zip file for lambda creation in moto
    import zipfile
    import io
    zip_output = io.BytesIO()
    zip_file = zipfile.ZipFile(zip_output, 'w', zipfile.ZIP_DEFLATED)
    zip_file.writestr('lambda_function.py', b'def lambda_handler(event, context):\n  return True\n')
    zip_file.close()
    zip_output.seek(0)
    zip_content = zip_output.read()

    lambda_client.create_function(
        FunctionName="test-lambda-1",
        Runtime="python3.9",
        Role=role["Role"]["Arn"],
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": zip_content}
    )
    
    resources = extractor.extract_resources()
    lambdas = [r for r in resources if r.type == NodeType.COMPUTE and ":function:" in r.id]
    
    assert len(lambdas) == 1
    assert lambdas[0].name == "test-lambda-1"
