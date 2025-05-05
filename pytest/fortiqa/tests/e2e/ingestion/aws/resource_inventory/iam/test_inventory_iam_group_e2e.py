import logging
import pytest
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_iam_group_helper import InventoryIAMGroupHelper

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_iam_group_helper(api_v2_client: APIV2Client) -> InventoryIAMGroupHelper:
    """Fixture to provide an instance of InventoryIAMGroupHelper for IAM Group inventory operations.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryIAMGroupHelper: An instance of InventoryIAMGroupHelper initialized with the provided API client.
    """
    return InventoryIAMGroupHelper(api_v2_client)


class TestResourceInventoryIAMGroupE2E:

    def test_inventory_search_iam_group_by_id_v2_e2e_daily_ingestion(self, inventory_iam_group_helper, random_iam_group, wait_for_daily_collection_completion_aws):
        """Verify if the IAM Group is present in the Lacework inventory by searching with the Group ID and account ID.

        Given:
         - An IAM Group with a specific Group ID and associated account ID.
         - An API client for interacting with the Lacework inventory API v2.
         - A time filter specifying the period of data collection completion.

        When:
         - The inventory search API v2 is called using the IAM Group's Group ID and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified IAM Group, identified by its Group ID and account ID.

        Args:
         inventory_iam_group_helper: Instance of InventoryIAMGroupHelper for interacting with Lacework's IAM Group inventory.
         random_iam_group: An 'IAMGroup' object representing a randomly selected IAM Group.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        time_filter = wait_for_daily_collection_completion_aws
        iam_group = random_iam_group
        if not iam_group:
            pytest.skip("There is no IAM Group available for testing.")

        api_response = inventory_iam_group_helper.retrieve_group_by_id(
            iam_group.group_id, iam_group.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['GroupId'] == iam_group.group_id, \
                f"IAM Group {iam_group.group_id} is not found in {data}"
