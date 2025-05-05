import logging
import pytest
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_ec2_volume_helper import InventoryEc2VolumeHelper

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_ec2_volume_helper(api_v2_client: APIV2Client) -> InventoryEc2VolumeHelper:
    """Fixture to provide an instance of InventoryEc2VolumeHelper for EC2 Volume inventory operations.

    This fixture initializes an InventoryEc2VolumeHelper instance, which allows test cases to interact with the Lacework
    inventory API for retrieving EC2 Volume-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryEc2VolumeHelper: An instance of InventoryEc2VolumeHelper initialized with the provided API client.
    """
    return InventoryEc2VolumeHelper(api_v2_client)


class TestResourceInventoryEc2VolumeE2E:

    @pytest.mark.parametrize('aws_region', ['us-east-2'], indirect=True)
    def test_inventory_search_volume_by_id_v2_e2e_daily_ingestion(self, inventory_ec2_volume_helper, random_volume, aws_region, wait_for_daily_collection_completion_aws):
        """Verify if the EC2 Volume is present in the Lacework inventory by searching with the Volume ID and account ID.

        Given:
         - An EC2 Volume with a specific ID and associated account ID.
         - An API client for interacting with the Lacework inventory API v2.
         - A time filter specifying the period of data collection completion.
         - A specific AWS region.

        When:
         - The inventory search API v2 is called using the Volume's ID and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified Volume, identified by its ID and account ID.

        Args:
         inventory_ec2_volume_helper: Instance of InventoryEc2VolumeHelper for interacting with Lacework's EC2 Volume inventory.
         random_volume: A 'Volume' object representing a randomly selected EC2 Volume.
         aws_region: AWS region where the EC2 Volume is located.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        time_filter = wait_for_daily_collection_completion_aws
        volume = random_volume
        if not volume:
            pytest.skip(f"There is no EC2 Volume in {aws_region}")

        api_response = inventory_ec2_volume_helper.retrieve_volume_by_id(
            volume.volume_id, volume.account_id, time_filter)
        assert api_response.status_code == 200, f"Expected status code 200 but got {api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        response_from_api_data = response_from_api['data']
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        for data in response_from_api_data:
            assert data['resourceConfig']['VolumeId'] == volume.volume_id, \
                f"EC2 Volume {volume.volume_id} is not found in {data}"
