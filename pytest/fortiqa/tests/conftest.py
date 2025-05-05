import logging
import time
import json
import pytest
from datetime import datetime, timedelta, timezone

from fortiqa.libs.lw.apiv2.api_client.inventory.inventory import InventoryV2
from fortiqa.libs.lw.apiv1.api_client.account_setting.account_setting import AccountSettingV1
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv1.api_client.api_v1_client import ApiV1Client
from fortiqa.libs.lw.apiv1.api_client.inventory.inventory import InventoryV1
from fortiqa.libs.lw.apiv2.api_client.cloud_accounts.cloud_accounts import CloudAccounts
from fortiqa.libs.terraform.tf_parser import TFParser
from fortiqa.libs.aws.cloudformation import CloudformationHelper
from fortiqa.tests.e2e.integrations.cloud_accounts.helpers import (
    generate_and_run_aws_eks_audit_cft,
    generate_and_run_aws_config_cft,
    generate_and_run_aws_cloudtrail_cft,
)
from fortiqa.tests import settings

logger = logging.getLogger(__name__)


def get_ingestion_period_after_completion(provider, api_v2_client: APIV2Client) -> dict[str, str] | None:
    """Monitors the ingestion period for a specified provider, checking for scan start and completion status.

    Args:
        provider (str): The cloud provider name (e.g., "AWS", "Azure").
        api_v2_client (APIV2Client): The API v2 client instance used for interaction.

    Returns:
        dict[str, str]: A dictionary containing the formatted start and end times of the ingestion period.
            - "startTime" (str): The start time of ingestion in UTC.
            - "endTime" (str): The end time of ingestion in UTC.

    Raises:
        Exception: If the scan has not started within 5 minutes post-ingestion, or if it has not completed within
            the expected 150 minutes.
    """
    logger.info(f"Checking ingestion status for {provider}")
    start_time_ingestion = datetime.now(timezone.utc)
    max_time_to_start_scan = start_time_ingestion + timedelta(minutes=5)
    inventory_instance = InventoryV2(api_v2_client)
    status = inventory_instance.get_scan_status(provider)['status']
    logger.info(f"scan status for {provider} = {status} ")
    while datetime.now(timezone.utc) < max_time_to_start_scan and status != "scanning":
        logger.debug("Waiting for scan to start, sleeping for 60 seconds...")
        time.sleep(60)
        status = inventory_instance.get_scan_status(provider)['status']
    if status != "scanning":
        raise Exception(f" For {provider} provider, Scan has not started within the expected 5 minutes post-ingestion.")
    logger.info("Scan is started")
    max_time_to_complete_scann = datetime.now(timezone.utc) + timedelta(minutes=150)
    while datetime.now(timezone.utc) < max_time_to_complete_scann and status != "available":
        logger.debug("Waiting for scan to complete, sleeping for 60 seconds...")
        time.sleep(60)
        status = inventory_instance.get_scan_status(provider)['status']
    if status != "available":
        raise Exception(f" For {provider} provider, Scan has not completed within the expected 150 minutes post-ingestion.")
    formatted_current_utc_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    formatted_start_time_ingestion = start_time_ingestion.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
            "startTime": formatted_start_time_ingestion,
            "endTime": formatted_current_utc_time
            }


def get_ingestion_period_after_daily_collection(provider, api_v1_client: ApiV1Client) -> dict[str, str] | None:
    """Wait for daily collection to be completed for the given provider.

    This method checks the time until the next daily collection start time for the specified provider.
    If the time until the daily collection is more than 2 hours, an exception is raised.
    Otherwise, it sleeps until the daily collection start time, and then checks the scan status every minute.
    If the scan status changes to 'pending', indicating that the scan and collection have been completed,
    it returns a time filter with the daily collection start time as 'startTime' and the current time as 'endTime'.
    If the scan status does not change to 'pending' within 4 hours and 30 minutes, an exception is raised.

    Args:
        provider (str): The name of the provider to check.
        api_v1_client (ApiV1Client): The API client instance used for making API calls.

    Returns:
        dict[str, str] | None: A dictionary containing 'startTime' and 'endTime' if the status changes to 'pending'.
                               Returns None if the scan status does not change to 'pending' within the allowed timeframe.

    Raises:
        Exception: If more than 2 hours remain until the daily collection start time.
        Exception: If the scan status does not change to 'pending' within 4 hours and 30 minutes.
    """
    logger.info(f"check daily collection for {provider}")
    account_setting_ins = AccountSettingV1(api_v1_client)
    next_daily_collection_start_time = account_setting_ins.get_next_collection_time()
    current_time = datetime.now(timezone.utc)
    time_difference = next_daily_collection_start_time - current_time
    difference_in_minutes = time_difference.total_seconds() / 60
    difference_in_hour = difference_in_minutes / 60
    if difference_in_hour > 2:
        raise Exception(
            f"More than 2 hours remain until the collection time. "
            f"{difference_in_hour:.2f} hrs remaining time to next collection."  # noqa: E231
        )

    logger.debug(f"Time to collection: {difference_in_minutes:.2f} minutes")     # noqa: E231
    inventory_ins = InventoryV1(api_v1_client)
    # Sleep until the collection start time with periodic updates
    logger.info(f"Sleeping until the collection start time: {next_daily_collection_start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    total_sleep_time = time_difference.total_seconds()
    sleep_interval = 600  # seconds

    while total_sleep_time > 0:
        if total_sleep_time >= sleep_interval:
            logger.info("Sleeping for the next 10 minutes...")
            time.sleep(sleep_interval)
            total_sleep_time -= sleep_interval
        else:
            logger.info(f"Sleeping for the remaining {total_sleep_time / 60:.2f} minutes...")  # noqa: E231
            time.sleep(total_sleep_time)
            total_sleep_time = 0

    # Calculate the end time as the collection start time + 6 hours and 30 minutes
    end_time = next_daily_collection_start_time + timedelta(hours=6, minutes=30)

    while datetime.now(timezone.utc) < end_time:
        status_dic = inventory_ins.get_scan_status(provider)
        status = status_dic['status']
        detail = status_dic['details']
        logger.debug(f"Status for {provider}: {status}, details: {detail}")
        if status == "pending":
            logger.info("Daily collection completed.")
            time_filter = {
                "startTime": next_daily_collection_start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                "endTime": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            }
            logger.info(f" Start and completion of daily collection = timeFilter: {time_filter}")
            return time_filter
        logger.info("Status is not yet pending, sleeping for 1 minute.")
        time.sleep(60)
    raise Exception(f"Status for {provider} did not change to 'pending' within 6 hours and 30 minutes.")


def pytest_addoption(parser):
    """
    This function adds two command-line options for pytest:
    1. `--tf_dir`: Specifies the path to a single Terraform working directory.
    2. `--tf_dir_list`: Specifies a file path containing a list of Terraform working directories.

    Args:
        parser: The pytest command-line parser object.
    """
    parser.addoption("--tf_dir", action="store", default="", help="Terraform working dir")
    parser.addoption("--tf_dir_list", action="store", default="", help="File with the list of TF working directories")


def get_name(obj: list | dict):
    """
    This function is used to retrieve the 'name' field from either a list of dictionaries
    or a single dictionary. If the input is a list, the names from all dictionaries are concatenated
    into a comma-separated string.

    Returns:
        str: The name(s) extracted from the input.
    """
    if isinstance(obj, list):
        return ','.join(map(lambda x: x['name'], obj))
    elif isinstance(obj, dict):
        return obj['name']


def pytest_generate_tests(metafunc):
    """
    This function loads Terraform configurations from either a single working directory
    or a list of working directories specified via command-line options. It parses the Terraform
    state and extracts cloud accounts, S3 buckets, IAM users, IAM roles, alert rules, and email
    alert channels. These extracted resources are then passed as parameters to the tests that
    request them.
    """
    tf_dir_list = []
    tf_dir_list_path = metafunc.config.getoption('tf_dir_list')
    tf_dir_path = metafunc.config.getoption('tf_dir')
    if tf_dir_list_path:
        with open(tf_dir_list_path) as f:
            tf_dir_list = f.read().splitlines()
    elif tf_dir_path:
        tf_dir_list = [tf_dir_path]
    tfparser = TFParser(working_dirs=tf_dir_list)
    tf_cloud_accounts = tfparser.get_lw_cloud_accounts() or []
    tf_s3_buckets = tfparser.get_s3_buckets() or []
    tf_iam_users = tfparser.get_iam_users() or []
    tf_iam_roles = tfparser.get_iam_roles() or []
    tf_lw_alert_rules = tfparser.get_lw_alert_rules() or []
    tf_lw_alert_profiles = tfparser.get_lw_alert_profiles() or []
    tf_lw_email_alert_channels = tfparser.get_lw_email_alert_channels() or []
    if 'tf_cloud_accounts' in metafunc.fixturenames:
        if tf_cloud_accounts:
            tf_cloud_accounts = [tf_cloud_accounts]
        metafunc.parametrize('tf_cloud_accounts', tf_cloud_accounts, ids=get_name)
    if 'tf_s3_buckets' in metafunc.fixturenames:
        if tf_s3_buckets:
            tf_s3_buckets = [tf_s3_buckets]
        metafunc.parametrize('tf_s3_buckets', tf_s3_buckets, ids=get_name)
    if 'tf_iam_users' in metafunc.fixturenames:
        metafunc.parametrize('tf_iam_users', tf_iam_users, ids=get_name)
    if 'tf_iam_roles' in metafunc.fixturenames:
        metafunc.parametrize('tf_iam_roles', tf_iam_roles, ids=get_name)
    if 'tf_lw_alert_rules' in metafunc.fixturenames:
        if tf_lw_alert_rules:
            tf_lw_alert_rules = [tf_lw_alert_rules]
        metafunc.parametrize('tf_lw_alert_rules', tf_lw_alert_rules, ids=get_name)
    if 'tf_lw_alert_profiles' in metafunc.fixturenames:
        if tf_lw_alert_profiles:
            tf_lw_alert_profiles = [tf_lw_alert_profiles]
        metafunc.parametrize('tf_lw_alert_profiles', tf_lw_alert_profiles, ids=get_name)
    if 'tf_lw_email_alert_channels' in metafunc.fixturenames:
        if tf_lw_email_alert_channels:
            tf_lw_email_alert_channels = [tf_lw_email_alert_channels]
        metafunc.parametrize('tf_lw_email_alert_channels', tf_lw_email_alert_channels, ids=get_name)


@pytest.fixture(scope='session')
def aws_account():
    """Fixture returns AWS account details from config.yaml"""
    return settings.app.aws_account


@pytest.fixture(scope='session')
def customer_account():
    """Fixture returns customer account details from config.yaml"""
    return settings.app.customer


@pytest.fixture(scope='session')
def aws_config_integration(aws_account, api_v2_client):
    """Fixture creates/deletes AWS Configuration integration."""
    cft_helper = CloudformationHelper(aws_credentials=aws_account.credentials)
    stack_id = generate_and_run_aws_config_cft(api_v2_client, aws_account.credentials)
    yield aws_account
    cft_helper.delete_stack_and_wait(stack_id)


@pytest.fixture(scope='session')
def aws_cloudtrail_and_config_integration(request, aws_account, api_v2_client):
    """Fixture creates/deletes AWS Cloudtrail+Configuration integration.

    TODO: Need to decide when to use this fixture vs aws_config_integration or how to use them at the same time.
    Because it also creates Configuration integration this fixture cannot be used in the same test run with aws_config_integration.
    """
    if not request.config.getoption("reuse_aws_account"):
        cft_helper = CloudformationHelper(aws_credentials=aws_account.credentials)
        stack_id = generate_and_run_aws_cloudtrail_cft(api_v2_client, aws_account.credentials)
        yield aws_account
        cft_helper.delete_stack_and_wait(stack_id)
    else:
        logger.info("reusing exicting aws account")
        yield aws_account


@pytest.fixture(scope='session')
def aws_eks_audit_log_integration(request, aws_account, api_v2_client):
    """Fixture creates/deletes AWS EKS Audit Log integration."""
    if not request.config.getoption("reuse_aws_account"):

        cft_helper = CloudformationHelper(aws_credentials=aws_account.credentials)
        stack_id = generate_and_run_aws_eks_audit_cft(api_v2_client, aws_account.credentials)
        yield aws_account
        cft_helper.delete_stack_and_wait(stack_id)
    else:
        logger.info("reusing exicting aws account")
        yield aws_account


@pytest.fixture(scope='session')
def aws_agentless_integration(request, aws_account, api_v2_client):
    """Fixture creates/deletes AWS EKS Audit Log integration."""
    if not request.config.getoption("reuse_aws_account"):

        cft_helper = CloudformationHelper(aws_credentials=aws_account.credentials)
        stack_id = generate_and_run_aws_eks_audit_cft(api_v2_client, aws_account.credentials)
        yield aws_account
        cft_helper.delete_stack_and_wait(stack_id)
    else:
        logger.info("reusing exicting aws account")
        yield aws_account


@pytest.fixture(scope='session')
def onboarded_aws_account(aws_account, api_v2_client, aws_eks_audit_log_integration, aws_cloudtrail_and_config_integration):
    """Fixture onboards same AWS account by adding Configuration, CloudTrail and EKS Audit Log integrations"""
    return aws_account


@pytest.fixture(scope='session')
def azure_account():
    """Fixture returns Azure account details from config.yaml"""
    return settings.app.azure_account


@pytest.fixture(scope='session')
def gcp_service_account():
    """Fixture returns GCP service account details from config.yaml"""
    return settings.app.gcp_service_account


@pytest.fixture(scope='session')
def terrafrom_remote_backend():
    """Fixture returns  terrafrom remote backend detail such as s3_bucket & s3_bucket_region"""
    return settings.app.terrafrom_remote_backend


@pytest.fixture(scope='session')
def onboarded_azure_account(azure_account, api_v2_client):
    """Fixture creates Azure Configuration integration"""
    payload = {
        'name': 'fortiqa-azure-cfg',
        'type': 'AzureCfg',
        'enabled': 1,
        'data': {
            'tenantId': azure_account.tenant_id,
            'credentials': {
                'clientId': azure_account.client_id,
                'clientSecret': azure_account.client_secret,
            },
        },
    }
    cld = CloudAccounts(api_v2_client)
    resp = cld.create_cloud_account(payload)
    onboarded_account = json.loads(resp.text)['data']
    yield onboarded_account
    cld.delete_cloud_account(intgGuid=onboarded_account['intgGuid'])


@pytest.fixture(scope="session")
def ingestion_completion_aws(api_v2_client, onboarded_aws_account) -> dict[str, str] | None:
    """Pytest fixture that waits for ingestion to complete after onboarding an AWS account and, upon completion, returns the ingestion period to be used as a time filter for future API calls.

    Args:
        api_v2_client (APIV2Client): The API client instance for interacting with AWS.
        onboarded_aws_account: Dependency fixture that ensures the AWS account is onboarded.

    Returns:
        dict[str, str] | None: A dictionary containing the start and end times of the ingestion period for AWS,
                            or None if ingestion could not be confirmed within the timeout period.
    """
    return get_ingestion_period_after_completion("AWS", api_v2_client)


@pytest.fixture(scope="session")
def ingestion_completion_azure(api_v2_client, onboarded_azure_account) -> dict[str, str] | None:
    """Pytest fixture that waits for ingestion to complete after onboarding an Azure account and, upon completion, returns the ingestion period to be used as a time filter for future API calls.

    Args:
        api_v2_client (APIV2Client): The API client instance for interacting with AWS.
        onboarded_azure_account: Dependency fixture that ensures the AZure account is onboarded.

    Returns:
        dict[str, str] | None: A dictionary containing the start and end times of the ingestion period for Azure,
                               or None if ingestion could not be confirmed within the timeout period.
    """
    return get_ingestion_period_after_completion("Azure", api_v2_client)


@pytest.fixture(scope="session")
def wait_for_daily_collection_completion_aws(api_v1_client) -> dict[str, str] | None:
    """Pytest fixture that waits for daily collection to complete for AWS

    This fixture uses the 'api_v1_client' fixture and 'AWS' as the provider
    to call 'get_ingestion_period_after_daily_collection'. If the next collection is more than 2 hours away,
    it raises an exception. If the collection completes within 4 hours and 30 minutes,
    it returns a dictionary with 'startTime' and 'endTime'; otherwise, an exception is raised.

    Note:
        - The onboarded_aws_account fixture was previously used to onboard and clean up the Aws account
          before and after tests. If onboarding logic is needed in the future, you can reintroduce it as
          an argument to this fixture and ensure proper onboarding/removal in your test flow.
    Args:
        api_v1_client: Fixture that provides an instance of `ApiV1Client` for interacting
                       with the Lacework API v1.

    Returns:
        dict[str, str] | None: A dictionary with 'startTime' and 'endTime' if the collection
                               completes successfully. Returns None if the collection does
                               not complete as expected.

    """
    return get_ingestion_period_after_daily_collection("AWS", api_v1_client)


@pytest.fixture(scope="session")
def wait_for_daily_collection_completion_azure(api_v1_client) -> dict[str, str] | None:
    """Pytest fixture that waits for daily collection to complete for Azure

    This fixture uses the 'api_v1_client' fixture and 'Azure' as the provider
    to call 'get_ingestion_period_after_daily_collection'. If the next collection is more than 2 hours away,
    it raises an exception. If the collection completes within 4 hours and 30 minutes,
    it returns a dictionary with 'startTime' and 'endTime'; otherwise, an exception is raised.
    Note:
        - The onboarded_azure_account fixture was previously used to onboard and clean up the Azure account
          before and after tests. If onboarding logic is needed in the future, you can reintroduce it as
          an argument to this fixture and ensure proper onboarding/removal in your test flow.


    Args:
        api_v1_client: Fixture that provides an instance of `ApiV1Client` for interacting
                       with the Lacework API v1.

    Returns:
        dict[str, str] | None: A dictionary with 'startTime' and 'endTime' if the collection
                               completes successfully. Returns None if the collection does
                               not complete as expected.

    """
    return get_ingestion_period_after_daily_collection("Azure", api_v1_client)


@pytest.fixture(scope="session")
def wait_for_daily_collection_completion_gcp(api_v1_client) -> dict[str, str] | None:
    """Pytest fixture that waits for daily collection to complete for GCP

    This fixture uses the 'api_v1_client' fixture and 'GCP' as the provider
    to call 'get_ingestion_period_after_daily_collection'. If the next collection is more than 2 hours away,
    it raises an exception. If the collection completes within 4 hours and 30 minutes,
    it returns a dictionary with 'startTime' and 'endTime'; otherwise, an exception is raised.
    Note:
        - The onboarded_GCP_account fixture can be  used to onboard and clean up the GCP account
          before and after tests. If onboarding logic is needed in the future, you can reintroduce it as
          an argument to this fixture and ensure proper onboarding/removal in your test flow.


    Args:
        api_v1_client: Fixture that provides an instance of `ApiV1Client` for interacting
                       with the Lacework API v1.

    Returns:
        dict[str, str] | None: A dictionary with 'startTime' and 'endTime' if the collection
                               completes successfully. Returns None if the collection does
                               not complete as expected.

    """
    return get_ingestion_period_after_daily_collection("GCP", api_v1_client)
