import logging
import pytest
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_iam_role_helper import InventoryIAMRoleHelper

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_iam_role_helper(api_v2_client: APIV2Client) -> InventoryIAMRoleHelper:
    """Fixture to provide an instance of InventoryIAMRoleHelper for IAM Role inventory operations.

    This fixture initializes an InventoryIAMRoleHelper instance, which allows test cases to interact with the Lacework
    inventory API for retrieving IAM Role-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryIAMRoleHelper: An instance of InventoryIAMRoleHelper initialized with the provided API client.
    """
    return InventoryIAMRoleHelper(api_v2_client)


class TestResourceInventoryIAMRoleE2E:

    def test_inventory_search_iam_role_by_id_v2_e2e_daily_ingestion(self, inventory_iam_role_helper, random_iam_role, wait_for_daily_collection_completion_aws):
        """Verify if the IAM Role is present in the Lacework inventory by searching with the Role ID and account ID.

        Given:
         - An IAM Role with a specific Role ID and associated account ID.
         - An API client for interacting with the Lacework inventory API v2.
         - A time filter specifying the period of data collection completion.

        When:
         - The inventory search API v2 is called using the IAM Role's Role ID and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified IAM Role, identified by its Role ID and account ID.

        Args:
         inventory_iam_role_helper: Instance of InventoryIAMRoleHelper for interacting with Lacework's IAM Role inventory.
         random_iam_role: An 'IAMRole' object representing a randomly selected IAM Role.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        time_filter = wait_for_daily_collection_completion_aws
        iam_role = random_iam_role
        if not iam_role:
            pytest.skip("There is no IAM Role available for testing.")

        api_response = inventory_iam_role_helper.retrieve_role_by_id(
            iam_role.role_id, iam_role.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['RoleId'] == iam_role.role_id, \
                f"IAM Role {iam_role.role_id} is not found in {data}"
