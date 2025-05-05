import logging
import pytest
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_vpc_helper import InventoryVPCHelper

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_vpc_helper(api_v2_client: APIV2Client) -> InventoryVPCHelper:
    """Fixture to provide an instance of InventoryVPCHelper for VPC inventory operations.

    This fixture initializes an InventoryVPCHelper instance, which allows test cases to interact with the Lacework
    inventory API for retrieving VPC-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryVPCHelper: An instance of InventoryVPCHelper initialized with the provided API client.
    """
    return InventoryVPCHelper(api_v2_client)


class TestResourceInventoryVPCE2E:

    @pytest.mark.parametrize('aws_region', ['us-east-2'], indirect=True)
    def test_inventory_search_vpc_by_id_v2_e2e_daily_ingestion(self, inventory_vpc_helper, random_vpc, aws_region, wait_for_daily_collection_completion_aws):
        """Verify if the VPC is present in the Lacework inventory by searching with the VPC ID and account ID.

        Given:
         - A VPC with a specific ID and associated account ID.
         - An API client for interacting with the Lacework inventory API v2.
         - A time filter specifying the period of data collection completion.
         - A specific AWS region.

        When:
         - The inventory search API v2 is called using the VPC's ID and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified VPC, identified by its VPC ID and account ID.

        Args:
         inventory_vpc_helper: Instance of InventoryVPCHelper for interacting with Lacework's VPC inventory.
         random_vpc: A 'VPC' object representing a randomly selected VPC.
        aws_region: AWS region where the VPC is located.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        time_filter = wait_for_daily_collection_completion_aws
        vpc = random_vpc
        if not vpc:
            pytest.skip(f"There is no VPC in {aws_region}")

        api_response = inventory_vpc_helper.reterive_vpc_by_vpc_id_lw(
            vpc.vpc_id, vpc.account_id, time_filter)
        assert api_response.status_code == 200, f"expected status code 200 but actual {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['VpcId'] == vpc.vpc_id, \
                f"VPC {vpc.vpc_id} is not found in {data}"
