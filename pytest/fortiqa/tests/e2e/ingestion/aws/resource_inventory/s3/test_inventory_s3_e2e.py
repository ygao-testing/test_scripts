import logging
import pytest
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_s3_helper import InventoryS3Helper
from fortiqa.libs.helper.date_helper import iso8601_to_datetime
from datetime import timedelta
logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_s3_helper(api_v2_client: APIV2Client) -> InventoryS3Helper:
    """Fixture to provide an instance of InventoryS3Helper for S3 inventory operations.

    This fixture initializes an InventoryS3Helper instance, which allows test cases to interact with the Lacework
    inventory API for retrieving S3-related resources.
    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryS3Helper: An instance of InventoryS3Helper initialized with the provided API client.
    """
    return InventoryS3Helper(api_v2_client)


class TestResourceInventoryS3E2E:

    @pytest.mark.dependency()
    def test_inventory_search_s3_bucket_by_name_v2_e2e_daily_ingestion(self, inventory_s3_helper, random_s3_bucket, wait_for_daily_collection_completion_aws):
        """Verify if the S3 bucket is present in the Lacework inventory by searching with the bucket name and account ID.

        Given:
         - An S3 bucket with a specific name and associated account ID.
         - An API client for interacting with the Lacework inventory API v2.
         - A time filter specifying the period of data collection completion to ensure recent data.

        When:
         - The inventory search API v2 is called using the S3 bucket's name and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified S3 bucket, identified by its name and account ID.

        Args:
         inventory_s3_helper: Instance of InventoryS3Helper for interacting with Lacework's S3 inventory.
         random_s3_bucket: An 'S3Bucket' object representing a randomly selected S3 bucket.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter
         """
        time_filter = wait_for_daily_collection_completion_aws
        s3_bucket = random_s3_bucket
        if not s3_bucket:
            pytest.skip("There is no S3 bucket availble")

        api_response = inventory_s3_helper.reterive_s3_bucket_by_name_from_lw(
            s3_bucket.name, s3_bucket.account_id, time_filter)
        assert api_response.status_code == 200, f"expected status code 200 but actual {
            api_response.status_code}"

        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['Name'] == s3_bucket.name, \
                f"S3 bucket  {s3_bucket.name} is not found in {data}"

    @pytest.mark.dependency(depends=["test_inventory_search_s3_bucket_by_name_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_s3_verify_creation_date_from_lacework_vs_aws_v2_e2e_daily_ingestion(self,  inventory_s3_helper, random_s3_bucket, wait_for_daily_collection_completion_aws):
        """Verify if the creation date of the S3 bucket matches between AWS and Lacework inventory.

        Given:
           - An S3 bucket with a known creation date.
           - An instance of InventoryS3Helper to interact with the Lacework inventory API.
           - A time filter specifying the period of daily collection completion.

        When:
           - The inventory search API v2 is called using the S3 bucket's name and account ID as filters.
           - The response from the Lacework inventory API is retrieved, and the S3 bucket's creation date from Lacework
             is compared to the creation date obtained from AWS.

        Then:
           - The API should return a 200 status code.
           - The response data should contain the specified S3 bucket with a creation date matching the one recorded in AWS.

        Args:
           inventory_s3_helper: Instance of InventoryS3Helper for interacting with Lacework's S3 inventory.
           random_s3_bucket: An 'S3Bucket' object representing a randomly selected S3 bucket.
           wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(
            f" Verifying  creation date for  s3 bucket :{random_s3_bucket}")
        time_filter = wait_for_daily_collection_completion_aws
        s3_bucket = random_s3_bucket

        if not s3_bucket:
            pytest.skip("There is no S3 bucket availble ")
        api_response = inventory_s3_helper.reterive_s3_bucket_by_name_from_lw(
            s3_bucket.name, s3_bucket.account_id, time_filter)
        assert api_response.status_code == 200, f"expected status code 200 but actual {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            lacework_creation_date = iso8601_to_datetime(
                data['resourceConfig']['CreationDate'])
            aws_s3_creation_date = iso8601_to_datetime(s3_bucket.creation_date)
            # Allow ±1 second tolerance
            assert aws_s3_creation_date - timedelta(seconds=1) <= lacework_creation_date <= aws_s3_creation_date + timedelta(seconds=1), \
                (f"S3 bucket {s3_bucket.name} has creation date: {aws_s3_creation_date} "
                 f"but Lacework returned {lacework_creation_date}")
