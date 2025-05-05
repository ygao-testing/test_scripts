import logging
import pytest
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_security_group_helper import InventorySecurityGroupHelper

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_security_group_helper(api_v2_client: APIV2Client) -> InventorySecurityGroupHelper:
    """Fixture to provide an instance of InventorySecurityGroupHelper for Security Group inventory operations.

    This fixture initializes an InventorySecurityGroupHelper instance, which allows test cases to interact with the Lacework
    inventory API for retrieving Security Group-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventorySecurityGroupHelper: An instance of InventorySecurityGroupHelper initialized with the provided API client.
    """
    return InventorySecurityGroupHelper(api_v2_client)


class TestResourceInventorySecurityGroupE2E:

    @pytest.mark.parametrize('aws_region', ['us-east-2'], indirect=True)
    def test_inventory_search_security_group_by_id_v2_e2e_daily_ingestion(self, inventory_security_group_helper, random_security_group, aws_region, wait_for_daily_collection_completion_aws):
        """Verify if the Security Group is present in the Lacework inventory by searching with the Security Group ID and account ID.

        Given:
         - A Security Group with a specific ID and associated account ID.
         - An API client for interacting with the Lacework inventory API v2.
         - A time filter specifying the period of data collection completion.
         - A specific AWS region.

        When:
         - The inventory search API v2 is called using the Security Group's ID and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified Security Group, identified by its ID and account ID.

        Args:
         inventory_security_group_helper: Instance of InventorySecurityGroupHelper for interacting with Lacework's Security Group inventory.
         random_security_group: A 'SecurityGroup' object representing a randomly selected Security Group.
         aws_region: AWS region where the Security Group is located.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """

        time_filter = wait_for_daily_collection_completion_aws
        security_group = random_security_group
        if not security_group:
            pytest.skip(f"There is no Security Group in {aws_region}")

        api_response = inventory_security_group_helper.retrieve_security_group_by_id(
            security_group.group_id, security_group.owner_id, time_filter)
        assert api_response.status_code == 200, f"expected status code 200 but actual {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['GroupId'] == security_group.group_id, \
                f"Security Group {security_group.group_id} is not found in {data}"
