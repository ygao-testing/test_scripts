import pytest
import logging
import os

from fortiqa.libs.aws.cloudformation import CloudformationHelper
from fortiqa.libs.lw.apiv1.helpers.cloud_logs.aws_cloudtrail_helper import CloudTrailHelper
from fortiqa.libs.aws.ec2 import EC2Helper
from fortiqa.tests.e2e.integrations.cloud_accounts.helpers import generate_and_run_aws_cloudtrail_cft
from fortiqa.tests.e2e.cloud_logs.conftest import apply_tf_modules, destroy_tf_modules


logger = logging.getLogger(__name__)


@pytest.fixture(scope='package')
def aws_env_variables(aws_account) -> None:
    """Fixture sets and deletes AWS credentials as env variables."""
    os.environ['AWS_ACCESS_KEY_ID'] = aws_account.aws_access_key_id
    os.environ['AWS_SECRET_ACCESS_KEY'] = aws_account.aws_secret_access_key
    yield
    del os.environ['AWS_ACCESS_KEY_ID']
    del os.environ['AWS_SECRET_ACCESS_KEY']


@pytest.fixture(scope="package")
def create_aws_audit_log_events(cloudlog_tf_root, aws_env_variables, cloudtrail_s3_bucket):
    """
    Fixture to:
    1. Deploy AWS resources (EC2, VPC, RouteTable, Security Group, S3 Bucket)
    2. Use Boto3 to do operations on deployed resources
    3. Destroy resources before onboarding AWS account
    """
    resources = {}
    tf_module = ["ec2_instance_and_s3_bucket"]
    resources = apply_tf_modules(tf_module, cloudlog_tf_root)
    tf_output = resources['ec2_instance_and_s3_bucket'].get('tf').output()
    region = tf_output['region']
    ec2_instance_id = tf_output['agent_host_instance_id']
    ec2_helper = EC2Helper(region=region)
    ec2_helper.create_tag_for_instance(instance_id=ec2_instance_id,
                                       tag_name="TestName",
                                       tag_value="cloudlog")
    ec2_helper.stop_instance(instance_id=ec2_instance_id)
    destroy_tf_modules(resources)
    return resources['ec2_instance_and_s3_bucket']


@pytest.fixture(scope="package")
def wait_for_cloudtrail_log(api_v1_client, cloudtrail_s3_bucket, aws_account, create_aws_audit_log_events):
    """Fixture to wait until CloudTrail logs appear inside Lacework"""
    resource_deploy_timestamp = create_aws_audit_log_events['deployment_timestamp']
    cloud_trail_helper = CloudTrailHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    cloud_trail_helper.wait_until_new_cloud_trail_log_appear(aws_account_id=aws_account.aws_account_id, aws_s3_bucket_name=cloudtrail_s3_bucket)
    # Cannot tell how long it takes to collect all Events we need, just wait until the last event to appear
    cloud_trail_helper.wait_until_specific_event_log_appear(aws_account_id=aws_account.aws_account_id, aws_s3_bucket_name=cloudtrail_s3_bucket, event_name="DeleteSecurityGroup")


@pytest.fixture(scope="package")
def on_board_cloud_trail_aws_account(aws_account, api_v2_client):
    """Fixture to on board AWS account through CloudTrail after operating resources"""
    cft_helper = CloudformationHelper(aws_credentials=aws_account.credentials)
    stack_id = generate_and_run_aws_cloudtrail_cft(api_v2_client, aws_account.credentials)
    yield stack_id
    cft_helper.delete_stack_and_wait(stack_id)


@pytest.fixture(scope="package")
def cloudtrail_s3_bucket(on_board_cloud_trail_aws_account, aws_account):
    """Fixture to return S3 bucket name to store the cloudtrail logs"""
    cft_helper = CloudformationHelper(aws_credentials=aws_account.credentials)
    s3_bucket_name = cft_helper.get_stack_resource_by_logical_id(stack_id=on_board_cloud_trail_aws_account,
                                                                 logical_res_id="LaceworkCWSBucket")
    return s3_bucket_name
