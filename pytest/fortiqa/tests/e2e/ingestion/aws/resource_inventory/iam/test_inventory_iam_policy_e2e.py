import logging
import pytest
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_iam_policy_helper import InventoryIAMPolicyHelper

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_iam_policy_helper(api_v2_client: APIV2Client) -> InventoryIAMPolicyHelper:
    """Fixture to provide an instance of InventoryIAMPolicyHelper for IAM Policy inventory operations.

    This fixture initializes an InventoryIAMPolicyHelper instance, which allows test cases to interact with the Lacework
    inventory API for retrieving IAM Policy-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryIAMPolicyHelper: An instance of InventoryIAMPolicyHelper initialized with the provided API client.
    """
    return InventoryIAMPolicyHelper(api_v2_client)


class TestResourceInventoryIAMPolicyE2E:

    def test_inventory_search_iam_policy_by_id_v2_e2e_daily_ingestion(self, inventory_iam_policy_helper, random_iam_policy, wait_for_daily_collection_completion_aws):
        """Verify if the IAM Policy is present in the Lacework inventory by searching with the Policy ID and account ID.

        Given:
         - An IAM Policy with a specific Policy ID and associated account ID.
         - An API client for interacting with the Lacework inventory API v2.
         - A time filter specifying the period of data collection completion.

        When:
         - The inventory search API v2 is called using the IAM Policy's Policy ID and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified IAM Policy, identified by its Policy ID and account ID.

        Args:
         inventory_iam_policy_helper: Instance of InventoryIAMPolicyHelper for interacting with Lacework's IAM Policy inventory.
         random_iam_policy: An 'IAMPolicy' object representing a randomly selected IAM Policy.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        time_filter = wait_for_daily_collection_completion_aws
        iam_policy = random_iam_policy
        if not iam_policy:
            pytest.skip("There is no IAM Policy available for testing.")

        api_response = inventory_iam_policy_helper.retrieve_policy_by_id(
            iam_policy.policy_id, iam_policy.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['PolicyId'] == iam_policy.policy_id, \
                f"IAM Policy {iam_policy.policy_id} is not found in {data}"
