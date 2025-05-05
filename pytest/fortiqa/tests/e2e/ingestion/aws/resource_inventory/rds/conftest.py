import logging
import pytest
from typing import Any
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_rds_db_instance_helper import InventoryRdsDbInstanceHelper
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response

logger = logging.getLogger(__name__)


@pytest.fixture(scope='module')
def inventory_rds_db_instance_helper(api_v2_client: APIV2Client) -> InventoryRdsDbInstanceHelper:
    """Fixture to provide an instance of InventoryRdsDbInstanceHelper for RDS DB Instance inventory operations.

    This fixture initializes an InventoryRdsDbInstanceHelper instance, which allows test cases to interact with the Lacework
    inventory API for retrieving RDS DB Instance-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryRdsDbInstanceHelper: An instance of InventoryRdsDbInstanceHelper initialized with the provided API client.
    """
    return InventoryRdsDbInstanceHelper(api_v2_client)


@pytest.fixture(scope="module")
def lacework_response_for_random_rds_db_instance(request, inventory_rds_db_instance_helper, random_rds_db_instance, wait_for_daily_collection_completion_aws) -> dict[str, Any] | None:
    """Fetch the Lacework inventory API response for a randomly selected RDS DB Instance.

    Args:
        inventory_rds_db_instance_helper: Instance of InventoryRdsDbInstanceHelper for interacting with the Lacework inventory.
        random_rds_db_instance: A randomly selected `DBInstance` object.
        Fixture ensuring daily ingestion collection is completed and providing a time filter.

    Returns:
        dict[str, Any] | None: The API response as a dictionary if the RDS DB Instance is found, or None otherwise.
    """
    time_filter = wait_for_daily_collection_completion_aws
    # time_filter = {
    #          "startTime": "2024-12-05T10:00:00.000Z",
    #         "endTime": "2024-12-06T12:00:000Z"
    #        }

    if random_rds_db_instance is None:
        pytest.skip("No RDS instance found in the given AWS region.")
    logger.info(f"Calling retrieve_db_instance_by_id with: identifier={
                random_rds_db_instance.db_instance_identifier}, account_id={random_rds_db_instance.account_id}, time_filter={time_filter}")
    api_response = inventory_rds_db_instance_helper.retrieve_db_instance_by_id(
        random_rds_db_instance.db_instance_identifier, random_rds_db_instance.account_id, time_filter
    )
    assert api_response.status_code == 200, f"Lacework API returned status {
        api_response.status_code} instead of 200."
    response_json = check_and_return_json_from_response(api_response)
    return response_json
