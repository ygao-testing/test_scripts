import logging
import pytest
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response

logger = logging.getLogger(__name__)


class TestResourceInventoryRdsDbInstanceE2E:

    @pytest.mark.parametrize('aws_region', ['us-east-2'], indirect=True)
    def test_inventory_search_rds_instance_by_id_v2_e2e_daily_ingestion(self, inventory_rds_db_instance_helper, random_rds_db_instance, aws_region, wait_for_daily_collection_completion_aws):
        """Verify if the RDS DB Instance is present in the Lacework inventory by searching with the DBInstanceIdentifier and account ID.

        Given:
         - An RDS DB Instance with a specific ID and associated account ID.
         - An API client for interacting with the Lacework inventory API v2.
         - A time filter specifying the period of data collection completion.
         - A specific AWS region.

        When:
         - The inventory search API v2 is called using the DBInstanceIdentifier and account ID as filters.

        Then:
         - The API should return a 200 status code.
         - The response data should contain only the specified RDS DB Instance, identified by its ID and account ID.

        Args:
         inventory_rds_db_instance_helper: Instance of InventoryRdsDbInstanceHelper for interacting with Lacework's RDS DB Instance inventory.
         random_rds_instance: A 'DBInstance' object representing a randomly selected RDS DB Instance.
         aws_region: AWS region where the RDS DB Instance is located.
         wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        time_filter = wait_for_daily_collection_completion_aws
        # time_filter = {
        #      "startTime": "2024-12-05T10:00:00.000Z",
        #     "endTime": "2024-12-06T12:00:000Z"
        #    }
        rds_instance = random_rds_db_instance
        if not rds_instance:
            pytest.skip(f"There is no RDS DB Instance in {aws_region}")

        api_response = inventory_rds_db_instance_helper.retrieve_db_instance_by_id(
            rds_instance.db_instance_identifier, rds_instance.account_id, time_filter)
        assert api_response.status_code == 200, f"Expected status code 200 but got {
            api_response.status_code}"
        response_from_api = check_and_return_json_from_response(api_response)
        logger.debug(f'Response body from Lacework: \n{response_from_api}')
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert data['resourceConfig']['DBInstanceIdentifier'] == rds_instance.db_instance_identifier, \
                f"RDS DB Instance {
                    rds_instance.db_instance_identifier} is not found in {data}"

    def test_resource_inventory_rds_db_instance_verify_db_instance_class_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, lacework_response_for_random_rds_db_instance, random_rds_db_instance):
        """
        Verify if the DBInstanceClass of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known DBInstanceClass.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed
            and providing a time filter.

        When:
            - The DBInstanceClass retrieved from AWS is compared with the DBInstanceClass present in the Lacework inventory.

        Then:
            - The DBInstanceClass from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
                                                        This fixture depends on 'wait_for_daily_collection_completion_aws'
                                                        to ensure data ingestion is complete.
            random_rds_db_instance: A 'DBInstance' object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance

        logger.debug(f" response from lacework API{response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.db_instance_class == data['resourceConfig']["DBInstanceClass"], \
                F"Expected DBInstanceClass '{random_rds_db_instance.db_instance_class}' from AWS but got '{
                    data['resourceConfig']['DBInstanceClass']}' from Lacework."

    def test_resource_inventory_rds_db_instance_verify_db_name_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, lacework_response_for_random_rds_db_instance, random_rds_db_instance):
        """
        Verify if the DBName of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known DBName.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed
            and providing a time filter.

        When:
            - The DBName retrieved from AWS is compared with the DBName present in the Lacework inventory.

        Then:
            - The DBName from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
                                                        This fixture depends on 'wait_for_daily_collection_completion_aws'
                                                        to ensure data ingestion is complete.
            random_rds_db_instance: A 'DBInstance' object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.db_name == data['resourceConfig']["DBName"], \
                f"Expected DBName {random_rds_db_instance.db_name} but got {
                    data['resourceConfig']['DBName']}."

    def test_resource_inventory_rds_db_instance_verify_engine_from_lacework_vs_aws_v2_e2e_daily_ingestion(self, lacework_response_for_random_rds_db_instance, random_rds_db_instance):
        """Verify if the Engine of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known Engine.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed
            and providing a time filter.

        When:
            - The Engine retrieved from AWS is compared with the Engine present in the Lacework inventory.

        Then:
            - The Engine from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
                                                        This fixture depends on 'wait_for_daily_collection_completion_aws'
                                                        to ensure data ingestion is complete.
            random_rds_db_instance: A 'DBInstance' object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.engine == data['resourceConfig']["Engine"], \
                f"Expected Engine {random_rds_db_instance.engine} but got {
                    data['resourceConfig']['Engine']}."

    def test_resource_inventory_rds_db_instance_verify_engine_version_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the EngineVersion of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known EngineVersion.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed
            and providing a time filter.

        When:
            - The EngineVersion retrieved from AWS is compared with the EngineVersion present in the Lacework inventory.

        Then:
            - The EngineVersion from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
                                                        This fixture depends on 'wait_for_daily_collection_completion_aws'
                                                        to ensure data ingestion is complete.
            random_rds_db_instance: A 'DBInstance' object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.engine_version == data['resourceConfig']["EngineVersion"], \
                f"Expected EngineVersion {random_rds_db_instance.engine_version} but got {
                    data['resourceConfig']['EngineVersion']}."

    def test_resource_inventory_rds_db_instance_verify_license_model_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the LicenseModel of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known LicenseModel.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed
            and providing a time filter.

        When:
            - The LicenseModel retrieved from AWS is compared with the LicenseModel present in the Lacework inventory.

        Then:
            - The LicenseModel from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
                                                        This fixture depends on 'wait_for_daily_collection_completion_aws'
                                                        to ensure data ingestion is complete.
            random_rds_db_instance: A 'DBInstance' object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.license_model == data['resourceConfig']["LicenseModel"], \
                f"Expected LicenseModel {random_rds_db_instance.license_model} but got {
                    data['resourceConfig']['LicenseModel']}."

    def test_resource_inventory_rds_db_instance_verify_multi_az_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the MultiAZ attribute of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known MultiAZ configuration.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed
            and providing a time filter.

        When:
            - The MultiAZ configuration retrieved from AWS is compared with the MultiAZ attribute present in the Lacework inventory.

        Then:
            - The MultiAZ attribute from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
                                                        This fixture depends on 'wait_for_daily_collection_completion_aws'
                                                        to ensure data ingestion is complete.
            random_rds_db_instance: A 'DBInstance' object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.multi_az == data['resourceConfig']["MultiAZ"], \
                f"Expected MultiAZ {random_rds_db_instance.multi_az} but got {
                    data['resourceConfig']['MultiAZ']}."

    def test_resource_inventory_rds_db_instance_verify_db_instance_status_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the DBInstanceStatus of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known DBInstanceStatus.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed
            and providing a time filter.

        When:
            - The DBInstanceStatus retrieved from AWS is compared with the DBInstanceStatus present in the Lacework inventory.

        Then:
            - The DBInstanceStatus from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
                                                        This fixture depends on 'wait_for_daily_collection_completion_aws'
                                                        to ensure data ingestion is complete.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.db_instance_status == data['resourceConfig']["DBInstanceStatus"], \
                f"Expected DBInstanceStatus {random_rds_db_instance.db_instance_status} but got {
                    data['resourceConfig']['DBInstanceStatus']}."

    def test_resource_inventory_rds_db_instance_verify_master_username_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the MasterUsername of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known MasterUsername.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed
            and providing a time filter.

        When:
            - The MasterUsername retrieved from AWS is compared with the MasterUsername present in the Lacework inventory.

        Then:
            - The MasterUsername from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
                                                        This fixture depends on 'wait_for_daily_collection_completion_aws'
                                                        to ensure data ingestion is complete.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.master_username == data['resourceConfig']["MasterUsername"], \
                f"Expected MasterUsername {random_rds_db_instance.master_username} but got {
                    data['resourceConfig']['MasterUsername']}."

    def test_resource_inventory_rds_db_instance_verify_endpoint_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the Endpoint of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known Endpoint.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed
            and providing a time filter.

        When:
            - The Endpoint retrieved from AWS is compared with the Endpoint present in the Lacework inventory.

        Then:
            - The Endpoint from AWS should match the one retrieved from Lacework, including Address, Port, and HostedZoneId.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
                                                        This fixture depends on 'wait_for_daily_collection_completion_aws'
                                                        to ensure data ingestion is complete.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            errors = []
            aws_endpoint = random_rds_db_instance.endpoint
            lacework_endpoint = data['resourceConfig'].get("Endpoint", {})
            # Validate each field and append failed assertions to errors
            if aws_endpoint.address != lacework_endpoint.get("Address"):
                errors.append(
                    f"Expected Endpoint Address {aws_endpoint.address} but got {
                        lacework_endpoint.get('Address')}."
                )
            if aws_endpoint.port != lacework_endpoint.get("Port"):
                errors.append(
                    f"Expected Endpoint Port {aws_endpoint.port} but got {
                        lacework_endpoint.get('Port')}."
                )
            if aws_endpoint.hosted_zone_id != lacework_endpoint.get("HostedZoneId"):
                errors.append(
                    f"Expected Endpoint HostedZoneId {aws_endpoint.hosted_zone_id} but got {
                        lacework_endpoint.get('HostedZoneId')}."
                )

            # Final assertion: If there are errors, fail with all the messages
            assert not errors, "\n".join(errors)

    def test_resource_inventory_rds_db_instance_verify_allocated_storage_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the AllocatedStorage of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known AllocatedStorage.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The AllocatedStorage retrieved from AWS is compared with the AllocatedStorage present in the Lacework inventory.

        Then:
            - The AllocatedStorage from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.allocated_storage == data['resourceConfig']["AllocatedStorage"], \
                f"Expected AllocatedStorage {random_rds_db_instance.allocated_storage} but got {
                    data['resourceConfig']['AllocatedStorage']}."

    def test_resource_inventory_rds_db_instance_verify_instance_create_time_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the InstanceCreateTime of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known InstanceCreateTime.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The InstanceCreateTime retrieved from AWS is compared with the InstanceCreateTime present in the Lacework inventory.

        Then:
            - The InstanceCreateTime from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.instance_create_time == data['resourceConfig']["InstanceCreateTime"], \
                f"Expected InstanceCreateTime {random_rds_db_instance.instance_create_time} but got {
                    data['resourceConfig']['InstanceCreateTime']}."

    def test_resource_inventory_rds_db_instance_verify_preferred_backup_window_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the PreferredBackupWindow of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known PreferredBackupWindow.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The PreferredBackupWindow retrieved from AWS is compared with the PreferredBackupWindow present in the Lacework inventory.

        Then:
            - The PreferredBackupWindow from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.preferred_backup_window == data['resourceConfig']["PreferredBackupWindow"], \
                f"Expected PreferredBackupWindow {random_rds_db_instance.preferred_backup_window} but got {
                    data['resourceConfig']['PreferredBackupWindow']}."

    def test_resource_inventory_rds_db_instance_verify_backup_retention_period_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the BackupRetentionPeriod of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known BackupRetentionPeriod.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The BackupRetentionPeriod retrieved from AWS is compared with the BackupRetentionPeriod present in the Lacework inventory.

        Then:
            - The BackupRetentionPeriod from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.backup_retention_period == data['resourceConfig']["BackupRetentionPeriod"], \
                f"Expected BackupRetentionPeriod {random_rds_db_instance.backup_retention_period} but got {
                    data['resourceConfig']['BackupRetentionPeriod']}."

    def test_resource_inventory_rds_db_instance_verify_db_security_groups_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the DBSecurityGroups of the RDS DB Instance match between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with known DBSecurityGroups.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The DBSecurityGroups retrieved from AWS are compared with the DBSecurityGroups present in the Lacework inventory.

        Then:
            - The DBSecurityGroups from AWS should match those retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.db_security_groups == data['resourceConfig']["DBSecurityGroups"], \
                f"Expected DBSecurityGroups {random_rds_db_instance.db_security_groups} but got {
                    data['resourceConfig']['DBSecurityGroups']}."

    def test_resource_inventory_rds_db_instance_verify_vpc_security_groups_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the VpcSecurityGroups of the RDS DB Instance match between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with known VpcSecurityGroups.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The VpcSecurityGroups retrieved from AWS are compared with the VpcSecurityGroups present in the Lacework inventory.

        Then:
            - The VpcSecurityGroups from AWS should match those retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            aws_vpc_security_groups = [
                {"VpcSecurityGroupId": sg.vpc_security_group_id, "Status": sg.status}
                for sg in random_rds_db_instance.vpc_security_groups
            ]
            lacework_vpc_security_groups = data['resourceConfig'].get(
                "VpcSecurityGroups", [])

            assert aws_vpc_security_groups == lacework_vpc_security_groups, \
                f"Expected VpcSecurityGroups {aws_vpc_security_groups} but got {
                    lacework_vpc_security_groups}."

    def test_resource_inventory_rds_db_instance_verify_db_parameter_groups_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the DBParameterGroups of the RDS DB Instance match between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with known DBParameterGroups.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The DBParameterGroups retrieved from AWS are compared with the DBParameterGroups present in the Lacework inventory.

        Then:
            - The DBParameterGroups from AWS should match those retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            aws_db_parameter_groups = [
                {"DBParameterGroupName": pg.db_parameter_group_name,
                    "ParameterApplyStatus": pg.parameter_apply_status}
                for pg in random_rds_db_instance.db_parameter_groups
            ]
            lacework_db_parameter_groups = data['resourceConfig'].get(
                "DBParameterGroups", [])

            assert aws_db_parameter_groups == lacework_db_parameter_groups, \
                f"Expected DBParameterGroups {aws_db_parameter_groups} but got {
                    lacework_db_parameter_groups}."

    def test_resource_inventory_rds_db_instance_verify_availability_zone_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the AvailabilityZone of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known AvailabilityZone.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The AvailabilityZone retrieved from AWS is compared with the AvailabilityZone present in the Lacework inventory.

        Then:
            - The AvailabilityZone from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.availability_zone == data['resourceConfig']["AvailabilityZone"], \
                f"Expected AvailabilityZone {random_rds_db_instance.availability_zone} but got {
                    data['resourceConfig']['AvailabilityZone']}."

    def test_resource_inventory_rds_db_instance_verify_db_subnet_group_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the DBSubnetGroup of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known DBSubnetGroup.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The DBSubnetGroup retrieved from AWS is compared with the DBSubnetGroup present in the Lacework inventory.

        Then:
            - The DBSubnetGroup from AWS should match the one retrieved from Lacework, including all its attributes.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            errors = []
            aws_subnet_group = random_rds_db_instance.db_subnet_group
            lacework_subnet_group = data['resourceConfig'].get(
                "DBSubnetGroup", {})

            # Validate top-level DBSubnetGroup fields
            if aws_subnet_group.db_subnet_group_name != lacework_subnet_group.get("DBSubnetGroupName"):
                errors.append(
                    f"Expected DBSubnetGroupName {aws_subnet_group.db_subnet_group_name} but got {
                        lacework_subnet_group.get('DBSubnetGroupName')}."
                )
            if aws_subnet_group.db_subnet_group_description != lacework_subnet_group.get("DBSubnetGroupDescription"):
                errors.append(
                    f"Expected DBSubnetGroupDescription {aws_subnet_group.db_subnet_group_description} but got {
                        lacework_subnet_group.get('DBSubnetGroupDescription')}."
                )
            if aws_subnet_group.vpc_id != lacework_subnet_group.get("VpcId"):
                errors.append(
                    f"Expected VpcId {aws_subnet_group.vpc_id} but got {
                        lacework_subnet_group.get('VpcId')}."
                )
            if aws_subnet_group.subnet_group_status != lacework_subnet_group.get("SubnetGroupStatus"):
                errors.append(
                    f"Expected SubnetGroupStatus {aws_subnet_group.subnet_group_status} but got {
                        lacework_subnet_group.get('SubnetGroupStatus')}."
                )

            # Validate subnets
            aws_subnets = aws_subnet_group.subnets
            lacework_subnets = lacework_subnet_group.get("Subnets", [])
            if len(aws_subnets) != len(lacework_subnets):
                errors.append(
                    f"Expected {len(aws_subnets)} subnets but got {
                        len(lacework_subnets)}."
                )
            else:
                for aws_subnet, lacework_subnet in zip(aws_subnets, lacework_subnets):
                    if aws_subnet.subnet_identifier != lacework_subnet.get("SubnetIdentifier"):
                        errors.append(
                            f"Expected SubnetIdentifier {aws_subnet.subnet_identifier} but got {
                                lacework_subnet.get('SubnetIdentifier')}."
                        )
                    if aws_subnet.availability_zone != lacework_subnet.get("SubnetAvailabilityZone", {}).get("Name"):
                        errors.append(
                            f"Expected AvailabilityZone {aws_subnet.availability_zone} but got {
                                lacework_subnet.get('SubnetAvailabilityZone', {}).get('Name')}."
                        )
                    if aws_subnet.status != lacework_subnet.get("SubnetStatus"):
                        errors.append(
                            f"Expected SubnetStatus {aws_subnet.status} but got {
                                lacework_subnet.get('SubnetStatus')}."
                        )

            # Final assertion: If there are errors, fail with all the messages
            assert not errors, "\n".join(errors)

    def test_resource_inventory_rds_db_instance_verify_preferred_maintenance_window_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the PreferredMaintenanceWindow of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known PreferredMaintenanceWindow.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The PreferredMaintenanceWindow retrieved from AWS is compared with the PreferredMaintenanceWindow present in the Lacework inventory.

        Then:
            - The PreferredMaintenanceWindow from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            aws_preferred_maintenance_window = random_rds_db_instance.preferred_maintenance_window
            lacework_preferred_maintenance_window = data['resourceConfig'].get(
                "PreferredMaintenanceWindow")

            assert aws_preferred_maintenance_window == lacework_preferred_maintenance_window, \
                f"Expected PreferredMaintenanceWindow {aws_preferred_maintenance_window} but got {
                    lacework_preferred_maintenance_window}."

    def test_resource_inventory_rds_db_instance_verify_pending_modified_values_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the PendingModifiedValues of the RDS DB Instance match between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with known PendingModifiedValues.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The PendingModifiedValues retrieved from AWS are compared with the PendingModifiedValues present in the Lacework inventory.

        Then:
            - The PendingModifiedValues from AWS should match those retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            aws_pending_modified_values = random_rds_db_instance.pending_modified_values
            lacework_pending_modified_values = data['resourceConfig'].get(
                "PendingModifiedValues")

            assert aws_pending_modified_values == lacework_pending_modified_values, \
                f"Expected PendingModifiedValues {aws_pending_modified_values} but got {
                    lacework_pending_modified_values}."

    def test_resource_inventory_rds_db_instance_verify_auto_minor_version_upgrade_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the AutoMinorVersionUpgrade of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known AutoMinorVersionUpgrade setting.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The AutoMinorVersionUpgrade setting retrieved from AWS is compared with the setting present in the Lacework inventory.

        Then:
            - The AutoMinorVersionUpgrade setting from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.auto_minor_version_upgrade == data['resourceConfig']["AutoMinorVersionUpgrade"], \
                f"Expected AutoMinorVersionUpgrade {random_rds_db_instance.auto_minor_version_upgrade} but got {
                    data['resourceConfig']['AutoMinorVersionUpgrade']}."

    def test_resource_inventory_rds_db_instance_verify_read_replica_db_instance_identifiers_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the ReadReplicaDBInstanceIdentifiers of the RDS DB Instance match between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with known ReadReplicaDBInstanceIdentifiers.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The ReadReplicaDBInstanceIdentifiers retrieved from AWS are compared with the ones present in the Lacework inventory.

        Then:
            - The ReadReplicaDBInstanceIdentifiers from AWS should match those retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']
        for data in response_from_api_data:
            assert random_rds_db_instance.read_replica_db_instance_identifiers == data['resourceConfig']["ReadReplicaDBInstanceIdentifiers"], \
                f"Expected ReadReplicaDBInstanceIdentifiers {random_rds_db_instance.read_replica_db_instance_identifiers} but got {
                    data['resourceConfig']['ReadReplicaDBInstanceIdentifiers']}."

    def test_resource_inventory_rds_db_instance_verify_option_group_memberships_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the OptionGroupMemberships of the RDS DB Instance match between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with known OptionGroupMemberships.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The OptionGroupMemberships retrieved from AWS are compared with the OptionGroupMemberships present in the Lacework inventory.

        Then:
            - The OptionGroupMemberships from AWS should match those retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            errors = []
            aws_option_groups = random_rds_db_instance.option_group_memberships
            lacework_option_groups = data['resourceConfig'].get(
                "OptionGroupMemberships", [])

            # Compare lengths
            if len(aws_option_groups) != len(lacework_option_groups):
                errors.append(
                    f"Expected {len(aws_option_groups)} OptionGroupMemberships but got {
                        len(lacework_option_groups)}."
                )

            # Compare individual memberships
            for aws_group, lacework_group in zip(aws_option_groups, lacework_option_groups):
                if aws_group.option_group_name != lacework_group.get("OptionGroupName"):
                    errors.append(
                        f"Expected OptionGroupName {aws_group.option_group_name} but got {
                            lacework_group.get('OptionGroupName')}."
                    )
                if aws_group.status != lacework_group.get("Status"):
                    errors.append(
                        f"Expected Status {aws_group.status} but got {
                            lacework_group.get('Status')}."
                    )

            # Final assertion: If there are errors, fail with all the messages
            assert not errors, "\n".join(errors)

    def test_resource_inventory_rds_db_instance_verify_publicly_accessible_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the PubliclyAccessible attribute of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known PubliclyAccessible value.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The PubliclyAccessible value retrieved from AWS is compared with the one present in the Lacework inventory.

        Then:
            - The PubliclyAccessible value from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.publicly_accessible == data['resourceConfig']["PubliclyAccessible"], \
                f"Expected PubliclyAccessible {random_rds_db_instance.publicly_accessible} but got {
                    data['resourceConfig']['PubliclyAccessible']}."

    def test_resource_inventory_rds_db_instance_verify_storage_type_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the StorageType of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known StorageType.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The StorageType retrieved from AWS is compared with the one present in the Lacework inventory.

        Then:
            - The StorageType from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.storage_type == data['resourceConfig']["StorageType"], \
                f"Expected StorageType {random_rds_db_instance.storage_type} but got {
                    data['resourceConfig']['StorageType']}."

    def test_resource_inventory_rds_db_instance_verify_db_instance_port_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the DbInstancePort of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known DbInstancePort.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The DbInstancePort retrieved from AWS is compared with the one present in the Lacework inventory.

        Then:
            - The DbInstancePort from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.db_instance_port == data['resourceConfig']["DbInstancePort"], \
                f"Expected DbInstancePort {random_rds_db_instance.db_instance_port} but got {
                    data['resourceConfig']['DbInstancePort']}."

    def test_resource_inventory_rds_db_instance_verify_storage_encrypted_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the StorageEncrypted attribute of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known StorageEncrypted value.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The StorageEncrypted value retrieved from AWS is compared with the one present in the Lacework inventory.

        Then:
            - The StorageEncrypted value from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.storage_encrypted == data['resourceConfig']["StorageEncrypted"], \
                f"Expected StorageEncrypted {random_rds_db_instance.storage_encrypted} but got {
                    data['resourceConfig']['StorageEncrypted']}."

    def test_resource_inventory_rds_db_instance_verify_dbi_resource_id_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the DbiResourceId of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known DbiResourceId.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The DbiResourceId retrieved from AWS is compared with the one present in the Lacework inventory.

        Then:
            - The DbiResourceId from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.dbi_resource_id == data['resourceConfig']["DbiResourceId"], \
                f"Expected DbiResourceId {random_rds_db_instance.dbi_resource_id} but got {
                    data['resourceConfig']['DbiResourceId']}."

    def test_resource_inventory_rds_db_instance_verify_ca_certificate_identifier_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the CACertificateIdentifier of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known CACertificateIdentifier.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The CACertificateIdentifier retrieved from AWS is compared with the one present in the Lacework inventory.

        Then:
            - The CACertificateIdentifier from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.certificate_details.ca_identifier == data['resourceConfig']["CACertificateIdentifier"], \
                f"Expected CACertificateIdentifier {random_rds_db_instance.certificate_details.ca_identifier} but got {
                    data['resourceConfig']['CACertificateIdentifier']}."

    def test_resource_inventory_rds_db_instance_verify_domain_memberships_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the DomainMemberships of the RDS DB Instance match between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known list of DomainMemberships.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The DomainMemberships retrieved from AWS are compared with the DomainMemberships present in the Lacework inventory.

        Then:
            - The DomainMemberships from AWS should match those retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            aws_domain_memberships = random_rds_db_instance.domain_memberships
            lacework_domain_memberships = data['resourceConfig'].get(
                "DomainMemberships", [])

            errors = []

            # Check length
            if len(aws_domain_memberships) != len(lacework_domain_memberships):
                errors.append(
                    f"Expected DomainMemberships length {len(aws_domain_memberships)} but got {
                        len(lacework_domain_memberships)}."
                )

            # Validate each membership
            for aws_membership, lacework_membership in zip(aws_domain_memberships, lacework_domain_memberships):
                if aws_membership.domain != lacework_membership.get("Domain"):
                    errors.append(
                        f"Expected Domain '{aws_membership.domain}' but got '{
                            lacework_membership.get('Domain')}'."
                    )
                if aws_membership.status != lacework_membership.get("Status"):
                    errors.append(
                        f"Expected Status '{aws_membership.status}' but got '{
                            lacework_membership.get('Status')}'."
                    )
                if aws_membership.fqdn != lacework_membership.get("FQDN"):
                    errors.append(
                        f"Expected FQDN '{aws_membership.fqdn}' but got '{
                            lacework_membership.get('FQDN')}'."
                    )
                if aws_membership.iam_role_name != lacework_membership.get("IAMRoleName"):
                    errors.append(
                        f"Expected IAMRoleName '{aws_membership.iam_role_name}' but got '{
                            lacework_membership.get('IAMRoleName')}'."
                    )
                if aws_membership.ou != lacework_membership.get("OU"):
                    errors.append(
                        f"Expected OU '{aws_membership.ou}' but got '{
                            lacework_membership.get('OU')}'."
                    )
                if aws_membership.auth_secret_arn != lacework_membership.get("AuthSecretArn"):
                    errors.append(
                        f"Expected AuthSecretArn '{aws_membership.auth_secret_arn}' but got '{
                            lacework_membership.get('AuthSecretArn')}'."
                    )
                if aws_membership.dns_ips != lacework_membership.get("DnsIps", []):
                    errors.append(
                        f"Expected DnsIps '{aws_membership.dns_ips}' but got '{
                            lacework_membership.get('DnsIps')}'."
                    )

            # Final assertion
            assert not errors, "\n".join(errors)

    def test_resource_inventory_rds_db_instance_verify_copy_tags_to_snapshot_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the CopyTagsToSnapshot attribute matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known CopyTagsToSnapshot value.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The CopyTagsToSnapshot value retrieved from AWS is compared with the one present in the Lacework inventory.

        Then:
            - The CopyTagsToSnapshot value from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.copy_tags_to_snapshot == data['resourceConfig']["CopyTagsToSnapshot"], \
                f"Expected CopyTagsToSnapshot {random_rds_db_instance.copy_tags_to_snapshot} but got {
                    data['resourceConfig']['CopyTagsToSnapshot']}."

    def test_resource_inventory_rds_db_instance_verify_monitoring_interval_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the MonitoringInterval of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known MonitoringInterval.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The MonitoringInterval retrieved from AWS is compared with the one present in the Lacework inventory.

        Then:
            - The MonitoringInterval from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.monitoring_interval == data['resourceConfig']["MonitoringInterval"], \
                f"Expected MonitoringInterval {random_rds_db_instance.monitoring_interval} but got {
                    data['resourceConfig']['MonitoringInterval']}."

    def test_resource_inventory_rds_db_instance_verify_db_instance_arn_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the DBInstanceArn matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known DBInstanceArn.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The DBInstanceArn retrieved from AWS is compared with the one present in the Lacework inventory.

        Then:
            - The DBInstanceArn from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.db_instance_arn == data['resourceConfig']["DBInstanceArn"], \
                f"Expected DBInstanceArn {random_rds_db_instance.db_instance_arn} but got {
                    data['resourceConfig']['DBInstanceArn']}."

    def test_resource_inventory_rds_db_instance_verify_iam_database_authentication_enabled_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the IAMDatabaseAuthenticationEnabled attribute matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known IAMDatabaseAuthenticationEnabled value.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The IAMDatabaseAuthenticationEnabled value retrieved from AWS is compared with the one present in the Lacework inventory.

        Then:
            - The IAMDatabaseAuthenticationEnabled value from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.iam_database_authentication_enabled == data['resourceConfig']["IAMDatabaseAuthenticationEnabled"], \
                f"Expected IAMDatabaseAuthenticationEnabled {random_rds_db_instance.iam_database_authentication_enabled} but got {
                    data['resourceConfig']['IAMDatabaseAuthenticationEnabled']}."

    def test_resource_inventory_rds_db_instance_verify_performance_insights_enabled_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the PerformanceInsightsEnabled of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known PerformanceInsightsEnabled status.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The PerformanceInsightsEnabled status retrieved from AWS is compared with the status present in the Lacework inventory.

        Then:
            - The PerformanceInsightsEnabled status from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.performance_insights_enabled == data['resourceConfig']["PerformanceInsightsEnabled"], \
                f"Expected PerformanceInsightsEnabled {random_rds_db_instance.performance_insights_enabled} but got {
                    data['resourceConfig']['PerformanceInsightsEnabled']}."

    def test_resource_inventory_rds_db_instance_verify_deletion_protection_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the DeletionProtection of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known DeletionProtection status.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The DeletionProtection status retrieved from AWS is compared with the status present in the Lacework inventory.

        Then:
            - The DeletionProtection status from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.deletion_protection == data['resourceConfig']["DeletionProtection"], \
                f"Expected DeletionProtection {random_rds_db_instance.deletion_protection} but got {
                    data['resourceConfig']['DeletionProtection']}."

    def test_resource_inventory_rds_db_instance_verify_associated_roles_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the AssociatedRoles of the RDS DB Instance match between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with known AssociatedRoles.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The AssociatedRoles retrieved from AWS are compared with the AssociatedRoles present in the Lacework inventory.

        Then:
            - The AssociatedRoles from AWS should match those retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.associated_roles == data['resourceConfig']["AssociatedRoles"], \
                f"Expected AssociatedRoles {random_rds_db_instance.associated_roles} but got {
                    data['resourceConfig']['AssociatedRoles']}."

    def test_resource_inventory_rds_db_instance_verify_max_allocated_storage_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the MaxAllocatedStorage of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known MaxAllocatedStorage value.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The MaxAllocatedStorage value retrieved from AWS is compared with the value present in the Lacework inventory.

        Then:
            - The MaxAllocatedStorage value from AWS should match the one retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            assert random_rds_db_instance.max_allocated_storage == data['resourceConfig']["MaxAllocatedStorage"], \
                f"Expected MaxAllocatedStorage {random_rds_db_instance.max_allocated_storage} but got {
                    data['resourceConfig']['MaxAllocatedStorage']}."

    def test_resource_inventory_rds_db_instance_verify_tags_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the tags of the RDS DB Instance match between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known set of tags stored as a dictionary.
            - A Lacework inventory API response containing the corresponding RDS DB Instance tags as a list.
            - The 'wait_for_daily_collection_completion_aws' fixture ensuring daily ingestion collection is completed.

        When:
            - The tags retrieved from AWS are compared with the tags present in the Lacework inventory.

        Then:
            - The tags from AWS should match those retrieved from Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            lacework_tags = {tag["Key"]: tag["Value"]
                             for tag in data['resourceConfig'].get("TagList", [])}
            aws_tags = random_rds_db_instance.tags

            assert aws_tags == lacework_tags, (
                f"Expected tags {aws_tags} but got {lacework_tags}."
            )

    def test_resource_inventory_rds_db_instance_verify_customer_owned_ip_enabled_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the CustomerOwnedIpEnabled of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known CustomerOwnedIpEnabled status.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The CustomerOwnedIpEnabled retrieved from AWS is compared with the status in Lacework inventory.

        Then:
            - The CustomerOwnedIpEnabled from AWS should match the one in Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        for data in response_from_api['data']:
            assert random_rds_db_instance.customer_owned_ip_enabled == data['resourceConfig']["CustomerOwnedIpEnabled"], \
                f"Expected CustomerOwnedIpEnabled {random_rds_db_instance.customer_owned_ip_enabled} but got {
                    data['resourceConfig']['CustomerOwnedIpEnabled']}."

    def test_resource_inventory_rds_db_instance_verify_activity_stream_status_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the ActivityStreamStatus of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known ActivityStreamStatus.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The ActivityStreamStatus retrieved from AWS is compared with the status in Lacework inventory.

        Then:
            - The ActivityStreamStatus from AWS should match the one in Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        for data in response_from_api['data']:
            assert random_rds_db_instance.activity_stream_status == data['resourceConfig']["ActivityStreamStatus"], \
                f"Expected ActivityStreamStatus {random_rds_db_instance.activity_stream_status} but got {
                    data['resourceConfig']['ActivityStreamStatus']}."

    def test_resource_inventory_rds_db_instance_verify_backup_target_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the BackupTarget of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known BackupTarget.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The BackupTarget retrieved from AWS is compared with the value in Lacework inventory.

        Then:
            - The BackupTarget from AWS should match the one in Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        for data in response_from_api['data']:
            assert random_rds_db_instance.backup_target == data['resourceConfig']["BackupTarget"], \
                f"Expected BackupTarget {random_rds_db_instance.backup_target} but got {
                    data['resourceConfig']['BackupTarget']}."

    def test_resource_inventory_rds_db_instance_verify_network_type_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the NetworkType of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known NetworkType.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The NetworkType retrieved from AWS is compared with the value in Lacework inventory.

        Then:
            - The NetworkType from AWS should match the one in Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        for data in response_from_api['data']:
            assert random_rds_db_instance.network_type == data['resourceConfig']["NetworkType"], \
                f"Expected NetworkType {random_rds_db_instance.network_type} but got {
                    data['resourceConfig']['NetworkType']}."

    def test_resource_inventory_rds_db_instance_verify_storage_throughput_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the StorageThroughput of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known StorageThroughput.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The StorageThroughput retrieved from AWS is compared with the value in Lacework inventory.

        Then:
            - The StorageThroughput from AWS should match the one in Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        for data in response_from_api['data']:
            assert random_rds_db_instance.storage_throughput == data['resourceConfig'].get("StorageThroughput", 0), \
                f"Expected StorageThroughput {random_rds_db_instance.storage_throughput} but got {
                    data['resourceConfig'].get('StorageThroughput', 0)}."

    def test_resource_inventory_rds_db_instance_verify_certificate_details_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the CertificateDetails of the RDS DB Instance match between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with known CertificateDetails.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The CertificateDetails retrieved from AWS are compared with the details in Lacework inventory.

        Then:
            - The CertificateDetails from AWS should match those in Lacework, including CAIdentifier and ValidTill.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        logger.info(f"Response from Lacework API: {response_from_api}")
        response_from_api_data = response_from_api['data']

        for data in response_from_api_data:
            errors = []
            aws_cert_details = random_rds_db_instance.certificate_details
            lacework_cert_details = data['resourceConfig'].get(
                "CertificateDetails")

            # Check if CertificateDetails exist in Lacework response
            if aws_cert_details and lacework_cert_details:
                # Validate CAIdentifier
                if aws_cert_details.ca_identifier != lacework_cert_details.get("CAIdentifier"):
                    errors.append(
                        f"Expected CAIdentifier {aws_cert_details.ca_identifier} but got {
                            lacework_cert_details.get('CAIdentifier')}."
                    )
                # Validate ValidTill
                if aws_cert_details.valid_till != lacework_cert_details.get("ValidTill"):
                    errors.append(
                        f"Expected ValidTill {aws_cert_details.valid_till} but got {
                            lacework_cert_details.get('ValidTill')}."
                    )
            elif aws_cert_details and not lacework_cert_details:
                errors.append(
                    "Expected CertificateDetails in Lacework response but got None.")
            elif not aws_cert_details and lacework_cert_details:
                errors.append(
                    "Unexpected CertificateDetails found in Lacework response.")

            # Final assertion: If there are errors, fail with all the messages
            assert not errors, "\n".join(errors)

    # @pytest.mark.xfail(reason='https://lacework.atlassian.net/browse/RAIN-94153')
    def test_resource_inventory_rds_db_instance_verify_dedicated_log_volume_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the DedicatedLogVolume of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known DedicatedLogVolume status.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The DedicatedLogVolume retrieved from AWS is compared with the value in Lacework inventory.

        Then:
            - The DedicatedLogVolume from AWS should match the one in Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        for data in response_from_api['data']:
            assert random_rds_db_instance.dedicated_log_volume == data['resourceConfig']["DedicatedLogVolume"], \
                f"Expected DedicatedLogVolume {random_rds_db_instance.dedicated_log_volume} but got {
                    data['resourceConfig']['DedicatedLogVolume']}."

    # @pytest.mark.xfail(reason='https://lacework.atlassian.net/browse/RAIN-94153')
    def test_resource_inventory_rds_db_instance_verify_is_storage_config_upgrade_available_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the IsStorageConfigUpgradeAvailable of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known IsStorageConfigUpgradeAvailable status.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The IsStorageConfigUpgradeAvailable retrieved from AWS is compared with the value in Lacework inventory.

        Then:
            - The IsStorageConfigUpgradeAvailable from AWS should match the one in Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        for data in response_from_api['data']:
            assert random_rds_db_instance.is_storage_config_upgrade_available == data['resourceConfig']["IsStorageConfigUpgradeAvailable"], \
                f"Expected IsStorageConfigUpgradeAvailable {random_rds_db_instance.is_storage_config_upgrade_available} but got {
                    data['resourceConfig']['IsStorageConfigUpgradeAvailable']}."

    def test_resource_inventory_rds_db_instance_verify_engine_lifecycle_support_from_lacework_vs_aws_v2_e2e_daily_ingestion(
        self, lacework_response_for_random_rds_db_instance, random_rds_db_instance
    ):
        """
        Verify if the EngineLifecycleSupport of the RDS DB Instance matches between AWS and Lacework inventory.

        Given:
            - An RDS DB Instance with a known EngineLifecycleSupport value.
            - A Lacework inventory API response containing the corresponding RDS DB Instance details.

        When:
            - The EngineLifecycleSupport retrieved from AWS is compared with the value in Lacework inventory.

        Then:
            - The EngineLifecycleSupport from AWS should match the one in Lacework.

        Args:
            lacework_response_for_random_rds_db_instance: The Lacework API response for the RDS DB Instance.
            random_rds_db_instance: A `DBInstance` object representing a randomly selected RDS DB Instance.
        """
        response_from_api = lacework_response_for_random_rds_db_instance
        for data in response_from_api['data']:
            assert random_rds_db_instance.engine_lifecycle_support == data['resourceConfig']["EngineLifecycleSupport"], \
                f"Expected EngineLifecycleSupport {random_rds_db_instance.engine_lifecycle_support} but got {
                    data['resourceConfig']["EngineLifecycleSupport"]}."
