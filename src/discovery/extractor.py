import boto3
import logging
from typing import List, Dict, Any
from src.models.common import Identity, Resource, NodeType

logger = logging.getLogger(__name__)

class Extractor:
    """
    Core implementation of the metadata extraction logic using Boto3.
    """
    
    def __init__(self, profile_name: str = None, region_name: str = 'us-east-1'):
        self.profile_name = profile_name
        self.region_name = region_name
        self.session = None
        self.iam_client = None
    
    def authenticate(self) -> bool:
        """Authenticate with AWS using Boto3."""
        try:
            # We use boto3.Session to allow explicit profile and region
            self.session = boto3.Session(profile_name=self.profile_name, region_name=self.region_name)
            self.iam_client = self.session.client('iam')
            # Test authentication by getting caller identity
            sts_client = self.session.client('sts')
            sts_client.get_caller_identity()
            logger.info("Successfully authenticated with AWS.")
            return True
        except Exception as e:
            logger.error(f"Failed to authenticate with AWS: {e}")
            return False

    def extract_identities(self) -> List[Identity]:
        """Extract IAM Users and Roles."""
        identities = []
        
        # 1. Extract Users
        try:
            paginator = self.iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    identities.append(
                        Identity(
                            id=user['Arn'],
                            name=user['UserName'],
                            type=NodeType.USER,
                            metadata=user
                        )
                    )
        except Exception as e:
            logger.error(f"Error extracting IAM users: {e}")

        # 2. Extract Roles
        try:
            paginator = self.iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    identities.append(
                        Identity(
                            id=role['Arn'],
                            name=role['RoleName'],
                            type=NodeType.ROLE,
                            metadata=role
                        )
                    )
        except Exception as e:
            logger.error(f"Error extracting IAM roles: {e}")

        return identities

    def _get_account_id(self) -> str:
        """Helper to get current AWS account ID for ARN construction."""
        if not hasattr(self, '_account_id'):
            try:
                sts = self.session.client('sts')
                self._account_id = sts.get_caller_identity()['Account']
            except Exception:
                self._account_id = "UNKNOWN_ACCOUNT"
        return self._account_id

    def extract_resources(self) -> List[Resource]:
        """Extract Resources (e.g., S3 Buckets, EC2 instances, Lambda, RDS)."""
        resources = []
        
        # S3 Buckets
        try:
            s3_client = self.session.client('s3')
            response = s3_client.list_buckets()
            for bucket in response.get('Buckets', []):
                resources.append(
                    Resource(
                        id=f"arn:aws:s3:::{bucket['Name']}",
                        name=bucket['Name'],
                        type=NodeType.STORAGE,
                        metadata={"CreationDate": bucket['CreationDate']}
                    )
                )
        except Exception as e:
            logger.error(f"Error extracting S3 buckets: {e}")

        # EC2 Instances
        try:
            ec2_client = self.session.client('ec2')
            paginator = ec2_client.get_paginator('describe_instances')
            for page in paginator.paginate():
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        instance_id = instance['InstanceId']
                        name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance_id)
                        resources.append(
                            Resource(
                                id=f"arn:aws:ec2:{self.region_name}:{self._get_account_id()}:instance/{instance_id}",
                                name=name,
                                type=NodeType.COMPUTE,
                                metadata={"State": instance.get('State', {}).get('Name'), "InstanceType": instance.get('InstanceType')}
                            )
                        )
        except Exception as e:
            logger.error(f"Error extracting EC2 instances: {e}")
            
        # Lambda Functions
        try:
            lambda_client = self.session.client('lambda')
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for func in page.get('Functions', []):
                    resources.append(
                        Resource(
                            id=func['FunctionArn'],
                            name=func['FunctionName'],
                            type=NodeType.COMPUTE,
                            metadata={"Runtime": func.get('Runtime'), "Role": func.get('Role')}
                        )
                    )
        except Exception as e:
            logger.error(f"Error extracting Lambda functions: {e}")

        # RDS Instances
        try:
            rds_client = self.session.client('rds')
            paginator = rds_client.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for db in page.get('DBInstances', []):
                    resources.append(
                        Resource(
                            id=db['DBInstanceArn'],
                            name=db['DBInstanceIdentifier'],
                            type=NodeType.STORAGE,
                            metadata={"Engine": db.get('Engine'), "DBInstanceStatus": db.get('DBInstanceStatus')}
                        )
                    )
        except Exception as e:
            logger.error(f"Error extracting RDS instances: {e}")

        return resources


