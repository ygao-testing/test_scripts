import json
import logging
import pytest
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.lw.apiv2.api_client.inventory.inventory_ec2_instance_helper import InventoryEC2Helper
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response, build_dynamic_payload

logger = logging.getLogger(__name__)


@pytest.fixture(scope='class')
def inventory_ec2_helper(api_v2_client: APIV2Client) -> InventoryEC2Helper:
    """Fixture to provide an instance of InventoryEC2Helper for EC2 inventory operations.

    This fixture initializes an InventoryEC2Helper instance, which allows test cases to interact with the Lacework
    inventory API for retrieving EC2-related resources.

    Args:
        api_v2_client (APIV2Client): The API client used to interact with the Lacework inventory API v2.

    Returns:
        InventoryEC2Helper: An instance of InventoryEC2Helper initialized with the provided API client.
    """
    return InventoryEC2Helper(api_v2_client)


@pytest.mark.order(1)
class TestResourceInventoryEC2InstanceE2E:

    @pytest.mark.parametrize('aws_region', ['us-east-2'], indirect=True)
    def test_inventory_find_all_ec2_instance_v2_e2e_daily_ingestion(self,  inventory_ec2_helper, all_aws_ec2_instances, aws_region, ingestion_tag, wait_for_daily_collection_completion_aws):
        """Verify if all expected EC2 instances are returned in the inventory, optionally filtered by ingestion tags.

        Given:
            - A list of EC2 instances (optionally filtered by `ingestion_tag`) and an account ID.
            - An instance of 'InventoryEC2Helper' for interacting with the Lacework inventory.
            - A time filter specifying the period of data collection completion.
            - A specific AWS region.

        When:
            - The inventory search API v2 is called with resourceType as 'ec2:instance', the account ID, and optional tags as filters.

        Then:
            - The API should return a 200 status code.
            - The test verifies that all expected EC2 instances are present in the API response.
            - Confirms that no unexpected EC2 instances are found in the response.
            - Asserts there are no missing EC2 instances by checking instance IDs against the expected list.

        Args:
            inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
            all_aws_ec2_instances: A list of expected EC2 instances in the specified region, filtered by 'ingestion_tag' if provided.
            aws_region: AWS region where the EC2 instances are located.
            ingestion_tag: A dictionary containing the key-value pair for filtering resources by tag. If None, no filtering is applied.
            wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        all_ec2_instances = all_aws_ec2_instances
        logger.info(f"Test find all EC2 instances in region: {aws_region}{
                    f', with tags {ingestion_tag}' if ingestion_tag else ''}")
        if not all_ec2_instances:
            pytest.skip(f"There is no ec2 instance in region: {aws_region}{
                        f', with tags {ingestion_tag}' if ingestion_tag else ''}")
        account_id = all_ec2_instances[0].account_id
        expected_instance_ids = {
            instance.instance_id for instance in all_ec2_instances}
        filters = [
            {"expression": "eq", "field": "resourceType", "value": "ec2:instance"},
            {"expression": "eq", "field": "cloudDetails.accountID", "value": account_id},
            {"expression": "eq", "field": "resourceRegion", "value": aws_region}
        ]
        if ingestion_tag:
            for key, value in ingestion_tag.items():
                filters.append(
                    {"expression": "eq", "field": f"resourceTags.{key}", "value": value})
        time_filter = wait_for_daily_collection_completion_aws
        payload = build_dynamic_payload(time_filter, filters, 'AWS')
        logger.info(f'payload: \n{payload}')
        api_response = inventory_ec2_helper.inventory.search_inventory(
            json.loads(payload))
        assert api_response.status_code == 200, f"expected status code 200 but actual {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        response_instance_ids = {data["resourceId"]
                                 for data in response_from_api_data}
        missing_instance = expected_instance_ids - response_instance_ids
        assert not missing_instance, f"Missing EC2 instances: {missing_instance} " \
            f" from expected instances: {expected_instance_ids}"
        extra_instances = response_instance_ids - expected_instance_ids
        assert not extra_instances, f"In addition to expected instances, Unexpected EC2 instances found in inventory: {
            extra_instances} "

    @pytest.mark.parametrize('aws_region', ['us-east-1', 'us-east-2', 'us-west-1', 'eu-west-1'], indirect=True)
    def test_inventory_search_ec2_instance_by_resourceId_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, aws_region, wait_for_daily_collection_completion_aws):
        """Verify if the EC2 instance is present in the inventory by searching with the resource ID.

        Given:
            - An EC2 instance with a resource ID.
            - An instance of 'InventoryEC2Helper' for interacting with the Lacework inventory.
            - A time filter specifying the period of data collection completion.
            - A specific AWS region.

        When:
            - The inventory search API v2 is called using the EC2 instance's resource ID as a filter.

        Then:
            - The API should return a 200 status code.
            - The response data should contain only the specified EC2 instance, identified by its resource ID.

        Args:
            inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
            random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
            aws_region: AWS region where the EC2 instance is located.
            wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip(f"There is no ec2 instance in region: {aws_region}")
        account_id = ec2_instance.account_id
        filters = [
            {"expression": "eq", "field": "resourceId",
                "value": ec2_instance.instance_id},
            {"expression": "eq", "field": "resourceType", "value": "ec2:instance"},
            {"expression": "eq", "field": "cloudDetails.accountID", "value": account_id},
            {"expression": "eq", "field": "resourceRegion", "value": aws_region}
        ]
        time_filter = wait_for_daily_collection_completion_aws
        payload = build_dynamic_payload(time_filter, filters, 'AWS')
        logger.info(f'payload: \n{payload}')
        api_response = inventory_ec2_helper.inventory.search_inventory(
            json.loads(payload))
        assert api_response.status_code == 200, f"expected status code 200 but actual {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceId'] == ec2_instance.instance_id, \
                f"resourceId {ec2_instance.instance_id} is not found in {data}"

    def test_inventory_search_ec2_instance_by_private_ip_address_v2_e2e_daily_ingestion(self, inventory_ec2_helper, ec2_instance_with_private_ip_address, aws_region, wait_for_daily_collection_completion_aws):
        """Verify if the EC2 instance is present in the inventory by searching with the private IP address.

        Given:
            - An EC2 instance with a private IP address.
            - An instance of 'InventoryEC2Helper' for interacting with the Lacework inventory.
            - A time filter specifying the period of data collection completion.
            - A specific AWS region.

        When:
            - The inventory search API v2 is called with resourceType as 'ec2:instance' and the EC2 instance's private IP address as a filter.

        Then:
            - The API should return a 200 status code.
            - Asserts that all returned EC2 instances in the response contain the specified private IP address.
            - Confirms that the EC2 instance with the specified private IP and instance ID is found in the API response.

        Args:
            inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
            ec2_instance_with_private_ip_address: An 'Ec2Instance' object representing an EC2 instance with a private IP.
            aws_region: AWS region where the EC2 instance is located.
            wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        ec2_instance = ec2_instance_with_private_ip_address
        if not ec2_instance:
            pytest.skip(
                f"There is no ec2 instance with private ip in region: {aws_region}")
        account_id = ec2_instance.account_id
        filters = [
            {"expression": "eq", "field": "resourceType", "value": "ec2:instance"},
            {"expression": "eq", "field": "resourceConfig.PrivateIpAddress",
                "value": ec2_instance.private_ip_address},
            {"expression": "eq", "field": "cloudDetails.accountID", "value": account_id},
            {"expression": "eq", "field": "resourceRegion", "value": aws_region}
        ]
        time_filter = wait_for_daily_collection_completion_aws
        payload = build_dynamic_payload(time_filter, filters, 'AWS')
        logger.info(f'payload: \n{payload}')
        api_response = inventory_ec2_helper.inventory.search_inventory(
            json.loads(payload))
        assert api_response.status_code == 200, f"expected status code 200 but actual {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        found = False
        for data in response_from_api['data']:
            assert data["resourceConfig"]["PrivateIpAddress"] == ec2_instance.private_ip_address, \
                f'EC2 INSTANCE with privete Ip Address {data["resourceConfig"]["PrivateIpAddress"]} \
                    found in response {data} instead of {ec2_instance.private_ip_address} '
            if data['resourceId'] == ec2_instance.instance_id:
                found = True
        assert found, f'EC2 instance {ec2_instance.instance_id} with private ip address {
            ec2_instance.private_ip_address} is not found in {response_from_api_data}'

    def test_inventory_search_ec2_instance_by_public_ip_address_v2_e2e_daily_ingestion(self, inventory_ec2_helper, ec2_instance_with_public_ip, aws_region, wait_for_daily_collection_completion_aws):
        """Verify if the EC2 instance is present in the inventory by searching with the public IP address.

        Given:
            - An EC2 instance with a public IP address.
            - An instance of 'InventoryEC2Helper' for interacting with the Lacework inventory.
            - A time filter specifying the period of data collection completion.
            - A specific AWS region.

        When:
            - The inventory search API v2 is called with resourceType as 'ec2:instance' and the EC2 instance's public IP address as filters.

        Then:
            - The API should return a 200 status code.
            - The test verifies that the EC2 instance is present in the API response with the specified public IP address.

        Args:
            inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
            ec2_instance_with_public_ip: An 'Ec2Instance' object representing an EC2 instance with a public IP.
            aws_region: AWS region where the EC2 instance is located.
            wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        ec2_instance = ec2_instance_with_public_ip
        if not ec2_instance:
            pytest.skip(
                f"There is no ec2 instance with private ip in region: {aws_region}")
        account_id = ec2_instance.account_id
        filters = [
            {"expression": "eq", "field": "resourceType", "value": "ec2:instance"},
            {"expression": "eq", "field": "resourceConfig.PublicIpAddress",
                "value": ec2_instance.public_ip_address},
            {"expression": "eq", "field": "cloudDetails.accountID", "value": account_id},
            {"expression": "eq", "field": "resourceRegion", "value": aws_region}
        ]
        time_filter = wait_for_daily_collection_completion_aws
        payload = build_dynamic_payload(time_filter, filters, 'AWS')
        logger.info(f'payload: \n{payload}')
        api_response = inventory_ec2_helper.inventory.search_inventory(
            json.loads(payload))
        assert api_response.status_code == 200, f"expected status code 200 but actual {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data["resourceConfig"]["PublicIpAddress"] == ec2_instance.public_ip_address, \
                f'EC2 INSTANCE with public Ip Address {data["resourceConfig"]["PublicIpAddress"]} ' \
                f'found in response {data} instead of {
                    ec2_instance.public_ip_address}'
            assert data['resourceId'] == ec2_instance.instance_id, \
                f'Expected EC2 instance {ec2_instance.instance_id} with public ip address {ec2_instance.public_ip_address}' \
                f'but EC2 insatce {data["resourceId"]} with public ip address {ec2_instance.public_ip_address} is found '\
                f'in response: \n {data}'

    def test_inventory_search_ec2_by_security_groups_v2_e2e_daily_ingestion(self, inventory_ec2_helper, ec2_instance_with_security_group, aws_region, wait_for_daily_collection_completion_aws):
        """Verify if EC2 instances associated with a specific security group are present in the inventory.

        Given:
            - A specific security group associated with an EC2 instance.
            - An API client for interacting with the Lacework inventory API v2.
            - A time filter specifying the period of data collection completion.
            - A specific AWS region.

        When:
            - The inventory search API v2 is called with resourceType as 'ec2:instance' and the security group as filters.

        Then:
            - The API should return a 200 status code.
            - The test verifies that the specified EC2 instance associated with the security group appears in the API response.
            - All instances in the inventory API response should have the specified security group.


        Args:
            inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
            ec2_instance_with_security_group: An 'Ec2Instance' object containing the security group and associated EC2 instance information.
            aws_region: AWS region where the EC2 instances are located.
            wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and return A time filter specifying the period of data collection completion.
        """
        if not ec2_instance_with_security_group:
            pytest.skip(
                f"There is no ec2 instance with security group in region: {aws_region}")
        sq_id = ec2_instance_with_security_group.security_groups[0].group_id
        filters = [
            {"expression": "eq", "field": "resourceType", "value": "ec2:instance"},
            {"expression": "rlike", "field": "resourceConfig.SecurityGroups",
                "value": f'.*{sq_id}.*'}
        ]
        time_filter = wait_for_daily_collection_completion_aws
        payload = build_dynamic_payload(time_filter, filters, 'AWS')
        logger.info(f'payload: \n{payload}')
        api_response = inventory_ec2_helper.inventory.search_inventory(
            json.loads(payload))
        assert api_response.status_code == 200, f"expected status code 200 but actual {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        response_instance_ids = {data["resourceId"]
                                 for data in response_from_api_data}
        assert ec2_instance_with_security_group.instance_id in response_instance_ids, f"EC2 instance {ec2_instance_with_security_group.instance_id} with security groupid: {sq_id} was not found in inventory search"  # noqa E713
        assert inventory_ec2_helper.inventory.check_if_all_ec2_has_specified_security_group(
            response_from_api_data, sq_id), f" Some instances in inventory search response do not have security group with groupid: {sq_id}"

    def test_inventory_search_ec2s_with_not_specified_security_groups_v2_e2e_daily_ingestion(self, inventory_ec2_helper, all_aws_ec2_instances, aws_region, wait_for_daily_collection_completion_aws):
        """Verify that EC2 instances without a specific security group are correctly retrieved from the inventory.

        Given:
            - A list of EC2 instances with associated security groups.
            - An instance of 'InventoryEC2Helper' for interacting with the Lacework inventory.
            - A time filter specifying the period of data collection completion.
            - A specific AWS region.

        When:
            - The test selects the first security group from an instance in the list of EC2 instances.
            - The test makes an API call to retrieve all EC2 instances that do not have this specified security group.

        Then:
            - If no EC2 instance in the API response contains the specific security group, the test passes.
            - The test verifies that the API response has a 204 status code when no instances without the specified security group are found.
            - When instances without the specified security group are found:
                - The test checks that the status code is 200.
                - Asserts that no EC2 instance in the API response contains the specified security group.
                - Ensures all instances in the EC2 Instance list without the specified security group are included in the API response.
                - Logs missing instance IDs if any are not returned in the API response.

        Args:
            inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
            all_aws_ec2_instances:  A list of EC2 instances to check in the specified region.
            aws_region: AWS region where the EC2 instances are located.
            wait_for_daily_collection_completion_aws: Fixture to ensure daily ingestion collection completion and provide a time filter for the data collection period.
        """
        if not all_aws_ec2_instances:
            pytest.skip(f"There is no ec2 instance in region: {aws_region}")
        account_id = all_aws_ec2_instances[0].account_id
        not_expected_sq = None
        for instance in all_aws_ec2_instances:
            if instance.security_groups:  # Check if the instance has security groups
                # Get groupId of first security group in the list
                not_expected_sq = instance.security_groups[0].group_id
                break
        # Skip the test if no security group was found
        if not_expected_sq is None:
            pytest.skip("No EC2 instance found with a security group")
        # Find instances that do not have the 'not_expected_sq' security group ID
        instances_without_not_expected_sq = [
            instance.instance_id for instance in all_aws_ec2_instances
            if not any(sg.group_id == not_expected_sq for sg in instance.security_groups)
        ]
        filters = [
            {"expression": "eq", "field": "resourceType", "value": "ec2:instance"},
            {"expression": "not_rlike", "field": "resourceConfig.SecurityGroups",
                "value": f".*{not_expected_sq}.*"},
            {"expression": "eq", "field": "cloudDetails.accountID", "value": account_id},
            {"expression": "eq", "field": "resourceRegion", "value": aws_region}
        ]
        time_filter = wait_for_daily_collection_completion_aws
        payload = build_dynamic_payload(time_filter, filters, 'AWS')
        logger.info(f'payload: \n{payload}')
        api_response = inventory_ec2_helper.inventory.search_inventory(
            json.loads(payload))
        if not instances_without_not_expected_sq:
            assert api_response.status_code == 204, f"expected status code 204 becuase there should not be any instances without security groupid {
                not_expected_sq}, but actual {api_response.status_code}"
        else:
            assert api_response.status_code == 200, f"expected status code 200 or 204 but actual {
                api_response.status_code}"
            response_from_api = check_and_return_json_from_response(
                api_response)
            logger.debug(f'Response body: \n{response_from_api}')
            response_from_api_data = response_from_api['data']
            # check if all EC2 instances from API response do not have the specified security group
            assert inventory_ec2_helper.inventory.check_if_all_ec2_lack_specified_security_group(
                response_from_api_data, not_expected_sq
            ), (
                f"Inventory search API found EC2 instances with the security group "
                f"{not_expected_sq}, but none were expected."
            )

            api_response_instance_ids = {
                data["resourceId"] for data in response_from_api_data}

            # Find instances in instances_without_not_expected_sq that are missing from the API response
            missing_instances = [
                instance_id for instance_id in instances_without_not_expected_sq
                if instance_id not in api_response_instance_ids
            ]

            # Assert that no instances are missing
            assert not missing_instances, (
                f"Expected all instances in {
                    instances_without_not_expected_sq} to be in the API response, "
                f"but the following instances were missing: {
                    missing_instances}"
            )
            logger.info(f"All EC2 instances in the inventory API response do not have the security group {
                        not_expected_sq}")

    @pytest.mark.dependency()
    def test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the EC2 instance is present in the Lacework inventory by searching with the InstanceId.

        Given:
         - An EC2 instance with a specific InstanceId and associated account ID.
         - An instance of 'InventoryEC2Helper' for interacting with the Lacework inventory.
         - A time filter specifying the period of data collection completion to ensure recent data.

        When:
         - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified EC2 instance, identified by its InstanceId.

        Args:
         inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
         random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available for testing.")
        time_filter = wait_for_daily_collection_completion_aws
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['InstanceId'] == ec2_instance.instance_id, \
                f"EC2 instance {ec2_instance.instance_id} not found in {data}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_image_id_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the ImageId of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known ImageId.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's ImageId from Lacework
            is compared to the ImageId obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with an ImageId matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying ImageId for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['ImageId'] == ec2_instance.image_id, \
                f"EC2 instance {ec2_instance.instance_id} has ImageId: {
                    ec2_instance.image_id} but Lacework returned {data['resourceConfig']['ImageId']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_instance_type_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the InstanceType of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known InstanceType.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's InstanceType from Lacework
        is compared to the InstanceType obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with an InstanceType matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying InstanceType for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['InstanceType'] == ec2_instance.instance_type, \
                f"EC2 instance {ec2_instance.instance_id} has InstanceType: {
                    ec2_instance.instance_type} but Lacework returned {data['resourceConfig']['InstanceType']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_private_dns_name_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the PrivateDnsName of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known PrivateDnsName.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's PrivateDnsName from Lacework
        is compared to the PrivateDnsName obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with a PrivateDnsName matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying PrivateDnsName for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['PrivateDnsName'] == ec2_instance.private_dns_name, \
                f"EC2 instance {ec2_instance.instance_id} has PrivateDnsName: {
                    ec2_instance.private_dns_name} but Lacework returned {data['resourceConfig']['PrivateDnsName']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_public_dns_name_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the PublicDnsName of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known PublicDnsName.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's PublicDnsName from Lacework
        is compared to the PublicDnsName obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with a PublicDnsName matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying PublicDnsName for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['PublicDnsName'] == ec2_instance.public_dns_name, \
                f"EC2 instance {ec2_instance.instance_id} has PublicDnsName: {
                    ec2_instance.public_dns_name} but Lacework returned {data['resourceConfig']['PublicDnsName']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_vpc_id_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the VpcId of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known VpcId.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's VpcId from Lacework
        is compared to the VpcId obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with a VpcId matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying VpcId for EC2 instance: {random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['VpcId'] == ec2_instance.vpc_id, \
                f"EC2 instance {ec2_instance.instance_id} has VpcId: {
                    ec2_instance.vpc_id} but Lacework returned {data['resourceConfig']['VpcId']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_subnet_id_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the SubnetId of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known SubnetId.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's SubnetId from Lacework
        is compared to the SubnetId obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with a SubnetId matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying SubnetId for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['SubnetId'] == ec2_instance.subnet_id, \
                f"EC2 instance {ec2_instance.instance_id} has SubnetId: {
                    ec2_instance.subnet_id} but Lacework returned {data['resourceConfig']['SubnetId']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_architecture_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the Architecture of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known Architecture.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's Architecture from Lacework
        is compared to the Architecture obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with an Architecture matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying Architecture for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['Architecture'] == ec2_instance.architecture, \
                f"EC2 instance {ec2_instance.instance_id} has Architecture: {
                    ec2_instance.architecture} but Lacework returned {data['resourceConfig']['Architecture']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_hypervisor_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the Hypervisor of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known Hypervisor.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's Hypervisor from Lacework
        is compared to the Hypervisor obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with a Hypervisor matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying Hypervisor for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['Hypervisor'] == ec2_instance.hypervisor, \
                f"EC2 instance {ec2_instance.instance_id} has Hypervisor: {
                    ec2_instance.hypervisor} but Lacework returned {data['resourceConfig']['Hypervisor']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_virtualization_type_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the VirtualizationType of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known VirtualizationType.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's VirtualizationType from Lacework
        is compared to the VirtualizationType obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with a VirtualizationType matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying VirtualizationType for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['VirtualizationType'] == ec2_instance.virtualization_type, \
                f"EC2 instance {ec2_instance.instance_id} has VirtualizationType: {
                    ec2_instance.virtualization_type} but Lacework returned {data['resourceConfig']['VirtualizationType']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_platform_details_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the PlatformDetails of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known PlatformDetails.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's PlatformDetails from Lacework
        is compared to the PlatformDetails obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with a PlatformDetails value matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying PlatformDetails for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['PlatformDetails'] == ec2_instance.platform_details, \
                f"EC2 instance {ec2_instance.instance_id} has PlatformDetails: {
                    ec2_instance.platform_details} but Lacework returned {data['resourceConfig']['PlatformDetails']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_usage_operation_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the UsageOperation of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known UsageOperation.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's UsageOperation from Lacework
        is compared to the UsageOperation obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with a UsageOperation value matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying UsageOperation for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['UsageOperation'] == ec2_instance.usage_operation, \
                f"EC2 instance {ec2_instance.instance_id} has UsageOperation: {
                    ec2_instance.usage_operation} but Lacework returned {data['resourceConfig']['UsageOperation']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_usage_operation_update_time_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the UsageOperationUpdateTime of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known UsageOperationUpdateTime.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's UsageOperationUpdateTime from Lacework
        is compared to the UsageOperationUpdateTime obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with a UsageOperationUpdateTime value matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying UsageOperationUpdateTime for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"

        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['UsageOperationUpdateTime'] == ec2_instance.usage_operation_update_time, \
                f"EC2 instance {ec2_instance.instance_id} has UsageOperationUpdateTime: {
                    ec2_instance.usage_operation_update_time} but Lacework returned {data['resourceConfig']['UsageOperationUpdateTime']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_state_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the State of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known State (code and name).
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's State (code and name) from Lacework
        is compared to the State obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with a State (code and name) matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying State for EC2 instance: {random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            api_state = data['resourceConfig']['State']
            aws_state = ec2_instance.state
            assert api_state['Code'] == aws_state.code, \
                f"EC2 instance {ec2_instance.instance_id} has State Code: {
                    aws_state.code} but Lacework returned {api_state['Code']}"
            assert api_state['Name'] == aws_state.name, \
                f"EC2 instance {ec2_instance.instance_id} has State Name: {
                    aws_state.name} but Lacework returned {api_state['Name']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_cpu_options_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the CpuOptions of the EC2 instance match between AWS and Lacework inventory.

        Given:
        - An EC2 instance with known CpuOptions (CoreCount and ThreadsPerCore).
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's CpuOptions from Lacework
        are compared to the CpuOptions obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with CpuOptions matching the ones recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying CpuOptions for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            api_cpu_options = data['resourceConfig']['CpuOptions']
            aws_cpu_options = ec2_instance.cpu_options
            assert api_cpu_options['CoreCount'] == aws_cpu_options.core_count, \
                f"EC2 instance {ec2_instance.instance_id} has CoreCount: {
                    aws_cpu_options.core_count} but Lacework returned {api_cpu_options['CoreCount']}"
            assert api_cpu_options['ThreadsPerCore'] == aws_cpu_options.threads_per_core, \
                f"EC2 instance {ec2_instance.instance_id} has ThreadsPerCore: {
                    aws_cpu_options.threads_per_core} but Lacework returned {api_cpu_options['ThreadsPerCore']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_ena_support_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the EnaSupport attribute of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known EnaSupport attribute.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's EnaSupport attribute from Lacework
        is compared to the value obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with an EnaSupport value matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying EnaSupport for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            api_ena_support = data['resourceConfig']['EnaSupport']
            aws_ena_support = ec2_instance.ena_support
            assert api_ena_support == aws_ena_support, \
                f"EC2 instance {ec2_instance.instance_id} has EnaSupport: {
                    aws_ena_support} but Lacework returned {api_ena_support}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_enclave_options_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the EnclaveOptions of the EC2 instance match between AWS and Lacework inventory.

        Given:
        - An EC2 instance with known EnclaveOptions (Enabled).
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's EnclaveOptions from Lacework
        are compared to the EnclaveOptions obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with EnclaveOptions matching the ones recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying EnclaveOptions for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            api_enclave_options = data['resourceConfig']['EnclaveOptions']
            aws_enclave_options = ec2_instance.enclave_options
            assert api_enclave_options['Enabled'] == aws_enclave_options.enabled, \
                f"EC2 instance {ec2_instance.instance_id} has EnclaveOptions.Enabled: {
                    aws_enclave_options.enabled} but Lacework returned {api_enclave_options['Enabled']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_ebs_optimized_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the EbsOptimized attribute of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known EbsOptimized attribute.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's EbsOptimized attribute from Lacework
        is compared to the value obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with an EbsOptimized value matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying EbsOptimized for EC2 instance: {
                    random_ec2_instance}")

        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            api_ebs_optimized = data['resourceConfig']['EbsOptimized']
            aws_ebs_optimized = ec2_instance.ebs_optimized
            assert api_ebs_optimized == aws_ebs_optimized, \
                f"EC2 instance {ec2_instance.instance_id} has EbsOptimized: {
                    aws_ebs_optimized} but Lacework returned {api_ebs_optimized}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_hibernation_options_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the HibernationOptions of the EC2 instance match between AWS and Lacework inventory.

        Given:
        - An EC2 instance with known HibernationOptions (Configured).
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's HibernationOptions from Lacework
        are compared to the HibernationOptions obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with HibernationOptions matching the ones recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying HibernationOptions for EC2 instance: {
                    random_ec2_instance}")
        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance
        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")
        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            api_hibernation_options = data['resourceConfig']['HibernationOptions']
            aws_hibernation_options = ec2_instance.hibernation_options
            assert api_hibernation_options['Configured'] == aws_hibernation_options.configured, \
                f"EC2 instance {ec2_instance.instance_id} has HibernationOptions.Configured: {
                    aws_hibernation_options.configured} but Lacework returned {api_hibernation_options['Configured']}"

    @pytest.mark.dependency(depends=["test_inventory_search_ec2_instance_by_instance_id_v2_e2e_daily_ingestion"], scope="class")
    def test_resource_inventory_ec2_verify_launch_time_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, inventory_ec2_helper, random_ec2_instance, wait_for_daily_collection_completion_aws):
        """Verify if the LaunchTime of the EC2 instance matches between AWS and Lacework inventory.

        Given:
        - An EC2 instance with a known LaunchTime.
        - An instance of InventoryEC2Helper to interact with the Lacework inventory API.
        - A time filter specifying the period of daily collection completion.

        When:
        - The inventory search API v2 is called using the EC2 instance's InstanceId and account ID as filters.
        - The response from the Lacework inventory API is retrieved, and the EC2 instance's LaunchTime from Lacework
        is compared to the LaunchTime obtained from AWS.

        Then:
        - The API should return a 200 status code.
        - The response data should contain the specified EC2 instance with a LaunchTime value matching the one recorded in AWS.

        Args:
        inventory_ec2_helper: Instance of InventoryEC2Helper for interacting with Lacework's EC2 inventory.
        random_ec2_instance: An 'Ec2Instance' object representing a randomly selected EC2 instance.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        logger.info(f"Verifying LaunchTime for EC2 instance: {random_ec2_instance}")

        time_filter = wait_for_daily_collection_completion_aws
        ec2_instance = random_ec2_instance

        if not ec2_instance:
            pytest.skip("There is no EC2 instance available.")

        api_response = inventory_ec2_helper.retrieve_ec2_instance_by_id_from_lw(
            ec2_instance.instance_id, ec2_instance.account_id, time_filter
        )
        assert api_response.status_code == 200, f"Expected status code 200 but got {api_response.status_code}"

        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f"Response body from Lacework: \n{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['LaunchTime'] == ec2_instance.launch_time, \
                f"EC2 instance {ec2_instance.instance_id} has LaunchTime: {ec2_instance.launch_time} but Lacework returned {data['resourceConfig']['LaunchTime']}"
