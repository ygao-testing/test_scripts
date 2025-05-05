import logging
import pytest
import json

from fortiqa.libs.lw.apiv1.helpers.cloud_logs.aws_cloudtrail_helper import CloudTrailHelper

logger = logging.getLogger(__name__)


def test_cloud_trail_events(api_v1_client, create_aws_audit_log_events, cloudtrail_s3_bucket, aws_account, wait_for_cloudtrail_log):
    """Test case for AWS CloudTrail Page -> Events graph

    Given: AWS CloudTrail integration finished, AWS resources deployed and operated by Boto3
    When: Check Cloud Logs->CloudTrail->Events graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_aws_audit_log_events: Deployed AWS resources
        cloudtrail_s3_bucket: S3 bucket created to store Cloud Trail logs
        aws_account: AWS account is being used
    """
    logger.info("Testing CloudTrail Event graph")
    resource_deploy_timestamp = create_aws_audit_log_events['deployment_timestamp']
    cloud_trail_helper = CloudTrailHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = cloud_trail_helper.get_cloud_trail_event_data_by_aws_account(aws_account_id=aws_account.aws_account_id)
    assert data, "Expected to find data inside Event graph, but found None"


def test_cloud_trail_usernames(api_v1_client, create_aws_audit_log_events, cloudtrail_s3_bucket, aws_account, wait_for_cloudtrail_log):
    """Test case for AWS CloudTrail Page -> Usernames graph

    Given: AWS CloudTrail integration finished, AWS resources deployed and operated by Boto3
    When: Check Cloud Logs->CloudTrail->Usernames graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_aws_audit_log_events: Deployed AWS resources
        cloudtrail_s3_bucket: S3 bucket created to store Cloud Trail logs
        aws_account: AWS account is being used
    """
    logger.info("Testing CloudTrail Unique Usernames graph")
    resource_deploy_timestamp = create_aws_audit_log_events['deployment_timestamp']
    cloud_trail_helper = CloudTrailHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = cloud_trail_helper.get_cloud_trail_unique_usernames_by_aws_account(aws_account_id=aws_account.aws_account_id)
    assert data, "Expected to find data inside Unique Usernames graph, but found None"


def test_cloud_trail_accounts(api_v1_client, create_aws_audit_log_events, cloudtrail_s3_bucket, aws_account, wait_for_cloudtrail_log):
    """Test case for AWS CloudTrail Page -> Unique Accounts graph

    Given: AWS CloudTrail integration finished, AWS resources deployed and operated by Boto3
    When: Check Cloud Logs->CloudTrail->Accounts graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_aws_audit_log_events: Deployed AWS resources
        cloudtrail_s3_bucket: S3 bucket created to store Cloud Trail logs
        aws_account: AWS account is being used
    """
    logger.info("Testing CloudTrail Unique Accounts graph")
    resource_deploy_timestamp = create_aws_audit_log_events['deployment_timestamp']
    cloud_trail_helper = CloudTrailHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = cloud_trail_helper.get_cloud_trail_unique_accounts_by_aws_account(aws_account_id=aws_account.aws_account_id)
    assert data, "Expected to find data inside Unique Accounts graph, but found None"


def test_cloud_trail_services(api_v1_client, create_aws_audit_log_events, cloudtrail_s3_bucket, aws_account, wait_for_cloudtrail_log):
    """Test case for AWS CloudTrail Page -> Unique Services graph

    Given: AWS CloudTrail integration finished, AWS resources deployed and operated by Boto3
    When: Check Cloud Logs->CloudTrail->Services graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_aws_audit_log_events: Deployed AWS resources
        cloudtrail_s3_bucket: S3 bucket created to store Cloud Trail logs
        aws_account: AWS account is being used
    """
    logger.info("Testing CloudTrail Unique Services graph")
    resource_deploy_timestamp = create_aws_audit_log_events['deployment_timestamp']
    cloud_trail_helper = CloudTrailHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = cloud_trail_helper.get_cloud_trail_unique_services_by_aws_account(aws_account_id=aws_account.aws_account_id)
    assert data, "Expected to find data inside Unique Services graph, but found None"


def test_cloud_trail_alerts(api_v1_client, create_aws_audit_log_events, cloudtrail_s3_bucket, aws_account, wait_for_cloudtrail_log):
    """Test case for AWS CloudTrail Page -> Alerts graph

    Given: AWS CloudTrail integration finished, AWS resources deployed and operated by Boto3
    When: Check Cloud Logs->CloudTrail->Alerts graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_aws_audit_log_events: Deployed AWS resources
        cloudtrail_s3_bucket: S3 bucket created to store Cloud Trail logs
        aws_account: AWS account is being used
    """
    logger.info("Testing CloudTrail Unique Alerts graph")
    resource_deploy_timestamp = create_aws_audit_log_events['deployment_timestamp']
    cloud_trail_helper = CloudTrailHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = cloud_trail_helper.get_cloud_trail_unique_alerts_by_aws_account(aws_account_id=aws_account.aws_account_id)
    assert data, "Expected to find data inside Unique Alerts graph, but found None"


def test_cloud_trail_apis(api_v1_client, create_aws_audit_log_events, cloudtrail_s3_bucket, aws_account, wait_for_cloudtrail_log):
    """Test case for AWS CloudTrail Page -> Unique APIs graph

    Given: AWS CloudTrail integration finished, AWS resources deployed and operated by Boto3
    When: Check Cloud Logs->CloudTrail->Alerts graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_aws_audit_log_events: Deployed AWS resources
        cloudtrail_s3_bucket: S3 bucket created to store Cloud Trail logs
        aws_account: AWS account is being used
    """
    logger.info("Testing CloudTrail Unique APIs graph")
    resource_deploy_timestamp = create_aws_audit_log_events['deployment_timestamp']
    cloud_trail_helper = CloudTrailHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = cloud_trail_helper.get_cloud_trail_unique_apis_by_aws_account(aws_account_id=aws_account.aws_account_id)
    assert data, "Expected to find data inside Unique APIs graph, but found None"


def test_cloud_trail_regions(api_v1_client, create_aws_audit_log_events, cloudtrail_s3_bucket, aws_account, wait_for_cloudtrail_log):
    """Test case for AWS CloudTrail Page -> Unique Regions graph

    Given: AWS CloudTrail integration finished, AWS resources deployed and operated by Boto3
    When: Check Cloud Logs->CloudTrail->Alerts graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_aws_audit_log_events: Deployed AWS resources
        cloudtrail_s3_bucket: S3 bucket created to store Cloud Trail logs
        aws_account: AWS account is being used
    """
    logger.info("Testing CloudTrail Unique Regions graph")
    resource_deploy_timestamp = create_aws_audit_log_events['deployment_timestamp']
    cloud_trail_helper = CloudTrailHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = cloud_trail_helper.get_cloud_trail_unique_regions_by_aws_account(aws_account_id=aws_account.aws_account_id)
    assert data, "Expected to find data inside Unique Regions graph, but found None"


def test_cloud_trail_user_details(api_v1_client, create_aws_audit_log_events, cloudtrail_s3_bucket, aws_account, wait_for_cloudtrail_log):
    """Test case for AWS CloudTrail Page -> User details dashboard

    Given: AWS CloudTrail integration finished, AWS resources deployed and operated by Boto3
    When: Check Cloud Logs->CloudTrail->Alerts graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_aws_audit_log_events: Deployed AWS resources
        cloudtrail_s3_bucket: S3 bucket created to store Cloud Trail logs
        aws_account: AWS account is being used
    """
    logger.info("Testing CloudTrail User details dashboard")
    resource_deploy_timestamp = create_aws_audit_log_events['deployment_timestamp']
    cloud_trail_helper = CloudTrailHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = cloud_trail_helper.get_cloud_trail_user_details_by_aws_account(aws_account_id=aws_account.aws_account_id)
    assert data, "Expected to find data inside User details dashboard, but found None"


def test_cloud_trail_user_events(api_v1_client, create_aws_audit_log_events, cloudtrail_s3_bucket, aws_account, wait_for_cloudtrail_log):
    """Test case for AWS CloudTrail Page -> User events dashboard

    Given: AWS CloudTrail integration finished, AWS resources deployed and operated by Boto3
    When: Check Cloud Logs->CloudTrail->Alerts graph
    Then: Expect it has data returned

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_aws_audit_log_events: Deployed AWS resources
        cloudtrail_s3_bucket: S3 bucket created to store Cloud Trail logs
        aws_account: AWS account is being used
    """
    logger.info("Testing CloudTrail User events dashboard")
    resource_deploy_timestamp = create_aws_audit_log_events['deployment_timestamp']
    cloud_trail_helper = CloudTrailHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    data = cloud_trail_helper.get_cloud_trail_user_events_by_aws_account(aws_account_id=aws_account.aws_account_id)
    assert data, "Expected to find data inside User events dashboard, but found None"


@pytest.mark.parametrize("expected_event", [
    "CreateSubnet",
    "CreateRoute",
    "CreateDhcpOptions",
    "CreateSecurityGroup",
    "CreateInternetGateway",
    "CreateRouteTable",
    "CreateRoute",
    "CreateSubnet",
    "CreateBucket",
    "RunInstances",
    "GetBucketAcl",
    "GetBucketVersioning",
    "AssociateRouteTable",
    "GetBucketTagging",
    "DescribeAvailabilityZones",
    "StopInstances",
    "CreateTags",
    "DeleteVpc",
    "DeleteSecurityGroup",
    "DeleteSubnet",
    "DetachInternetGateway",
    "DeleteInternetGateway",
    "DeleteSubnet",
    "TerminateInstances",
    "DisassociateRouteTable",
    "DeleteBucket",
    "DeleteRouteTable",
    "DisassociateRouteTable",
    "DeleteDhcpOptions"
])
def test_cloud_trail_logs(api_v1_client, create_aws_audit_log_events, cloudtrail_s3_bucket, aws_account, expected_event, wait_for_cloudtrail_log):
    """Test case for AWS CloudTrail logs

    Given: AWS CloudTrail integration finished, AWS resources deployed and operated by Boto3
    When: Check Cloud Logs->CloudTrail
    Then: Expected Event Name should appear

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        create_aws_audit_log_events: Deployed AWS resources
        cloudtrail_s3_bucket: S3 bucket created to store Cloud Trail logs
        aws_account: AWS account is being used
        expected_event: Expected Event_Name
    """
    logger.info(f"Testing {expected_event}...")
    resource_deploy_timestamp = create_aws_audit_log_events['deployment_timestamp']
    cloud_trail_helper = CloudTrailHelper(api_v1_client, fix_timestamp=resource_deploy_timestamp)
    all_logs = cloud_trail_helper.get_cloud_trail_logs_by_aws_account(aws_account_id=aws_account.aws_account_id)
    found = False
    for log in all_logs:
        if log['EVENT_NAME'] == expected_event and cloudtrail_s3_bucket in log['S3_URL']:
            found = True
            break
    assert found, f"Expected to find Event Name={expected_event} with S3 Bucket: {cloudtrail_s3_bucket}, but found nothing. Last collected logs: {json.dumps(all_logs, indent=2)}"
