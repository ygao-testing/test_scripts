import logging
import pytest
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_iam_user_helper import InventoryIAMUserHelper

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_iam_user_helper(api_v2_client: APIV2Client) -> InventoryIAMUserHelper:
    """Fixture to provide an instance of InventoryIAMUserHelper for IAM User inventory operations.

    This fixture initializes an InventoryIAMUserHelper instance, which allows test cases to interact with the Lacework
    inventory API for retrieving IAM User-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryIAMUserHelper: An instance of InventoryIAMUserHelper initialized with the provided API client.
    """
    return InventoryIAMUserHelper(api_v2_client)


class TestResourceInventoryIAMUserE2E:

    def test_inventory_search_iam_user_by_id_v2_e2e_daily_ingestion(self, inventory_iam_user_helper, random_iam_user, wait_for_daily_collection_completion_aws):
        """Verify if the IAM User is present in the Lacework inventory by searching with the User ID and account ID.

        Given:
         - An IAM User with a specific User ID and associated account ID.
         - An API client for interacting with the Lacework inventory API v2.
         - A time filter specifying the period of data collection completion.

        When:
         - The inventory search API v2 is called using the IAM User's User ID and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified IAM User, identified by its User ID and account ID.

        Args:
         inventory_iam_user_helper: Instance of InventoryIAMUserHelper for interacting with Lacework's IAM User inventory.
         random_iam_user: An 'IAMUser' object representing a randomly selected IAM User.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        time_filter = wait_for_daily_collection_completion_aws
        iam_user = random_iam_user
        if not iam_user:
            pytest.skip("There is no IAM User available for testing.")

        api_response = inventory_iam_user_helper.retrieve_user_by_id(
            iam_user.user_id, iam_user.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['UserId'] == iam_user.user_id, \
                f"IAM User {iam_user.user_id} is not found in {data}"
