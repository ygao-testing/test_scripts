import pytest
import logging
from datetime import datetime, timezone
from fortiqa.libs.helper.date_helper import get_time_range_6_days_back_7am_to_next_day_659am_utc_epoch
from fortiqa.libs.lw.apiv1.api_client.cloud_compliance.cloud_compliance import CloudComplianceV1, get_expected_compliance_by_resource_type
from fortiqa.libs.helper.date_helper import iso8601_to_datetime, datetime_to_timestamp

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def get_start_time_range_end_time_range_epoch_utc():
    """
    Fixture to provide start and end time range in epoch milliseconds for testing.

    - "StartTimeRange": 7 days before tomorrow at 07:00:00 UTC
    - "EndTimeRange": tomorrow at 06:59:59.999 UTC


    Returns:
        dict[str, int]: Dictionary with StartTimeRange and EndTimeRange in epoch milliseconds.
    """
    return get_time_range_6_days_back_7am_to_next_day_659am_utc_epoch()


@pytest.fixture(scope="session")
def cloud_compliance_v1_client(api_v1_client):
    """
    Provides an instance of CloudComplianceV1 to interact with the Lacework Cloud Compliance API.

    Given:
        - A Lacework API V1 client.
    Returns:
        - A CloudComplianceV1 instance that can be used to make cloud compliance API calls.
    """
    return CloudComplianceV1(api_v1_client)


@pytest.fixture(scope="session")
def wait_for_cloud_compliance_policy_update_aws(aws_account, wait_for_daily_collection_completion_aws, get_start_time_range_end_time_range_epoch_utc, cloud_compliance_v1_client) -> dict[str, int]:
    """
    Wait for Lacework Cloud Compliance policy assessment update for AWS after ingestion.

    This fixture polls the CloudCompliance_PolicyStats endpoint and checks whether all LAST_EVAL_TIME values
    in the response are greater than or equal to the expected assessment time (ingestion start).

    The fixture:
    - Computes timeout as 90 minutes after actual ingestion completion.
    - Logs how long the update took if successful.
    - Raises TimeoutError if updates aren't detected in time.

    Args:
        aws_account: Fixture that provides AWS account metadata.
        wait_for_daily_collection_completion_aws: Fixture that ensures ingestion is complete and returns time window.
        get_start_time_range_end_time_range_epoch_utc: Fixture providing a consistent start/end range for policy queries.
        cloud_compliance_v1_client: Fixture providing CloudComplianceV1 client instance.

    Returns:
        dict[str, int]: Dictionary with keys 'start_time_range' and 'end_time_range' (both in epoch ms).
    """
    cloud_compliance = cloud_compliance_v1_client
    aws_account_id = aws_account.aws_account_id

    ingestion_start_dt = iso8601_to_datetime(wait_for_daily_collection_completion_aws["startTime"])
    ingestion_end_dt = iso8601_to_datetime(wait_for_daily_collection_completion_aws["endTime"])
    current_time = datetime.now(timezone.utc)

    start_time_range = get_start_time_range_end_time_range_epoch_utc["StartTimeRange"]
    end_time_range = get_start_time_range_end_time_range_epoch_utc["EndTimeRange"]

    elapsed_since_ingestion_sec = (current_time - ingestion_end_dt).total_seconds()
    timeout_after_ingestion_sec = 90 * 60
    remaining_time_sec = max(60, timeout_after_ingestion_sec - elapsed_since_ingestion_sec)

    logger.info("Checking cloud compliance policy update for AWS...")
    logger.info(f"Time since ingestion completed: {elapsed_since_ingestion_sec:.2f} seconds")
    logger.info(f"Allowed time remaining to detect update: {remaining_time_sec:.2f} seconds")

    update_completed = cloud_compliance.check_for_policy_update(
        start_time_range=start_time_range,
        end_time_range=end_time_range,
        cloud_provider="AWS",
        provider_ids=[aws_account_id],
        expected_assessment_time=datetime_to_timestamp(ingestion_start_dt),
        timeout_seconds=int(remaining_time_sec)
    )

    if update_completed:
        update_time = datetime.now(timezone.utc)
        logger.info(f"Cloud compliance policies updated {int((update_time - ingestion_end_dt).total_seconds())} seconds after ingestion ccompletion.")
        return {
            "start_time_range": start_time_range,
            "end_time_range": end_time_range
        }
    else:
        raise TimeoutError(f"Cloud compliance policy update not completed within {remaining_time_sec:.2f} seconds after ingestion completion.")


@pytest.fixture(scope="session")
def expected_compliance_iam_roles_by_policy(e2e_aws_resources) -> dict[str, dict[str, list[str]]]:
    """
    Fixture that returns expected compliance status for deployed IAM roles, grouped by policy ID.

    Returns:
        dict: Mapping of policy_id to {"compliant": [...], "non_compliant": [...]} based on Terraform deployment.
    """
    return get_expected_compliance_by_resource_type(e2e_aws_resources, "iam-role")


@pytest.fixture(scope="session")
def expected_compliance_iam_groups_by_policy(e2e_aws_resources) -> dict[str, dict[str, list[str]]]:
    """
    Fixture that returns expected compliance status for deployed IAM groups, grouped by policy ID.

    Returns:
        dict: Mapping of policy_id to {"compliant": [...], "non_compliant": [...]} based on Terraform deployment.
    """
    return get_expected_compliance_by_resource_type(e2e_aws_resources, "iam-group")


@pytest.fixture(scope="session")
def expected_compliance_iam_users_by_policy(e2e_aws_resources) -> dict[str, dict[str, list[str]]]:
    """
    Fixture that returns expected compliance status for deployed IAM users, grouped by policy ID.

    Returns:
        dict: Mapping of policy_id to {"compliant": [...], "non_compliant": [...]} based on Terraform deployment.
    """
    return get_expected_compliance_by_resource_type(e2e_aws_resources, "iam-user")
