import os
import json
import pytest
import logging
import random
import string
import time
import boto3

from fortiqa.libs.terraform.tf_helper import TFHelper
from fortiqa.libs.aws.s3 import S3Helper

logger = logging.getLogger(__name__)
random_id = ''.join(random.choices(string.ascii_letters, k=4))
tf_owner_prefix = f'fortiqa_iam_user_alerts_{random_id}'
SLEEP_TIMEOUT = 300
QUERY_TIMEOUT = 400
FILTER_TIME_RANGE = '10 minutes'

@pytest.fixture(scope='session')
def aws_iam_user_tf_root(request) -> str:
    """Fixture returns root folder for lacework provider TF modules."""
    root = os.path.join(request.config.rootdir, '../terraform/')
    print(f'{root=}')
    return root

@pytest.fixture(scope='session')
def aws_user(aws_init_s3_bucket, aws_iam_user_tf_root, aws_account):
    """Fixture applies all TF modules for aws users."""
    users = {}
    try:
        os.environ['AWS_ACCESS_KEY_ID'] = aws_account.aws_access_key_id
        os.environ['AWS_SECRET_ACCESS_KEY'] = aws_account.aws_secret_access_key
        os.environ['TF_VAR_USER_NAME'] = 'lw_alert_user'
        users = TFHelper(tf_owner_prefix).apply_tf_modules(
            ["iam_user"],
            aws_iam_user_tf_root,
            aws_account.aws_terraform_s3_backend,
            aws_account.aws_terraform_s3_backend_region,
        )
        yield users
    finally:
        TFHelper(tf_owner_prefix).destroy_tf_modules(users)
        s3_helper = S3Helper(
            region=aws_account.aws_terraform_s3_backend_region,
            aws_credentials=aws_account.credentials,
        )
        s3_helper.delete_file(
            bucket_name=aws_account.aws_terraform_s3_backend,
            file_path=users['iam_user']['backend_key'],
        )


@pytest.fixture(scope='session')
def cis_aws_tf_root(request) -> str:
    """Fixture returns root folder for lacework provider TF modules."""
    root = os.path.join(request.config.rootdir, '../terraform/')
    print(f'{root=}')
    return root


@pytest.fixture(scope='session')
def cis_aws_setup(aws_init_s3_bucket, cis_aws_tf_root, aws_account):
    """Fixture applies all TF modules for cis aws framework."""
    
    cis_aws_resources = {}
    try:
        os.environ['AWS_ACCESS_KEY_ID'] = aws_account.aws_access_key_id
        os.environ['AWS_SECRET_ACCESS_KEY'] = aws_account.aws_secret_access_key
        #os.environ['TF_VAR_USER_NAME'] = 'cis_aws_user'
        cis_aws_resources = TFHelper(tf_owner_prefix).apply_tf_modules(
            ["cis_aws"],
            cis_aws_tf_root,
            aws_account.aws_terraform_s3_backend,
            aws_account.aws_terraform_s3_backend_region,
        )
        yield cis_aws_resources
        
    finally:
        TFHelper(tf_owner_prefix).destroy_tf_modules(cis_aws_resources)
        s3_helper = S3Helper(
            region=aws_account.aws_terraform_s3_backend_region,
            aws_credentials=aws_account.credentials,
        )
        s3_helper.delete_file(
            bucket_name=aws_account.aws_terraform_s3_backend,
            file_path=cis_aws_resources['cis_aws']['backend_key'],
        )


def generate_event_PutGroupPolicy(aws_account): 
    iam = boto3.client('iam',
                       aws_access_key_id=aws_account.aws_access_key_id, 
                       aws_secret_access_key=aws_account.aws_secret_access_key, 
                       region_name=aws_account.aws_terraform_s3_backend_region)
    group_name = "yning_script_group_1"
    policy_name = "yning_script_group_policy_1"
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "*"
            }
        ]
    }

    iam.put_group_policy(
        GroupName=group_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_document)
    )

    logger.info(f'---event "PutGroupPolicy" generated---')
    logger.info(f'---this event may trigger "Identity and Access Management (IAM) Policy Change"---')



def generate_event_PutBucketPolicy(aws_account): 
    s3 = boto3.client('s3',
                      aws_access_key_id=aws_account.aws_access_key_id, 
                      aws_secret_access_key=aws_account.aws_secret_access_key, 
                      region_name=aws_account.aws_terraform_s3_backend_region)
    BUCKET_NAME = 'yning-script-s3-bucket-1'
    BUCKET_POLICY_DOCUMENT = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{BUCKET_NAME}/*"
            }
        ]
    }
    
    s3.put_bucket_policy(
        Bucket=BUCKET_NAME,
        Policy=json.dumps(BUCKET_POLICY_DOCUMENT)
    )

    logger.info(f'---event "PutBucketPolicy" generated---')
    logger.info(f'---this event may trigger "S3 Bucket Policy Change"---')



def generate_event_CreateVpc(aws_account): 
    ec2 = boto3.client('ec2',
                       aws_access_key_id=aws_account.aws_access_key_id, 
                       aws_secret_access_key=aws_account.aws_secret_access_key, 
                       region_name=aws_account.aws_terraform_s3_backend_region
    )
    VPC_NAME = 'yning-script-vpc-1'

    policy_response = ec2.create_vpc(
        CidrBlock='10.0.0.0/16',
        TagSpecifications=[{
            'ResourceType': 'vpc',
            'Tags': [{'Key': 'Name', 'Value': VPC_NAME}]
        }]
    )
    vpc_id = policy_response['Vpc']['VpcId']

    logger.info(f'---event "CreateVpc" generated---')
    logger.info(f'{vpc_id=}')
    logger.info(f'---this event may trigger "Virtual Private Cloud (VPC) Change" and "New Virtual Private Cloud (VPC)"---')

    return vpc_id



def generate_event_DeleteVpc(aws_account, vpc_id): 
    time.sleep(3)
    ec2 = boto3.client('ec2',
                       aws_access_key_id=aws_account.aws_access_key_id, 
                       aws_secret_access_key=aws_account.aws_secret_access_key, 
                       region_name=aws_account.aws_terraform_s3_backend_region
    )

    ec2.delete_vpc(VpcId=vpc_id)

    logger.info(f'---event "DeleteVpc" triggered---')
    logger.info(f'---this event may trigger "Virtual Private Cloud (VPC) Change"---')


    
def generate_event_CreateUser_DeleteUser(aws_account): 
    iam_client = boto3.client('iam',
                              aws_access_key_id=aws_account.aws_access_key_id, 
                              aws_secret_access_key=aws_account.aws_secret_access_key, 
                              region_name=aws_account.aws_terraform_s3_backend_region)
    USER_NAME = "autocase_user"

    iam_client.create_user(UserName=USER_NAME)

    logger.info(f'---event "CreateUser" generated---')
    logger.info(f'---this event may trigger "New AWS User Created"---')

    time.sleep(3)

    iam_client.delete_user(UserName=USER_NAME)
    logger.info(f'---event "DeleteUser" generated---')
    logger.info(f'---this event may not trigger policy or alert---')




