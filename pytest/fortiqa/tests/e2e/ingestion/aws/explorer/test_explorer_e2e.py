import logging
import time
import pytest

from datetime import datetime, timezone, timedelta
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard
from fortiqa.libs.lw.apiv1.payloads import GraphQLFilter, ComparisonOperator
from fortiqa.libs.lw.apiv1.helpers.graphql_helper import GraphQLHelper
from fortiqa.libs.lw.apiv1.api_client.graph_ql.graph_ql import GraphQL
from fortiqa.tests.e2e.ingestion.aws.tf_modules import iam_user_and_accessible_s3_bucket_tf_modules
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response

logger = logging.getLogger(__name__)


class TestExplorerE2E:

    # @pytest.mark.xfail(raises=TimeoutError, reason='https://lacework.atlassian.net/browse/PSP-2964')
    @pytest.mark.skip(reason='There is no explorer api to return the  latest update for aws cloud provider')
    def test_explorer_last_update_post_daily_ingestion(self, api_v1_client, wait_for_daily_collection_completion_aws):
        """Verify that the last update time in the Explorer matches the daily ingestion completion timeframe.

        Given:
            - An API client to interact with the Lacework API v1.
            - A time filter specifying the daily ingestion collection completion period.

        When:
            - The Explorer API is queried for the last update timestamp post daily collection.

        Then:
            - The API should return a 200 status code.
            - The last update timestamp from the Explorer is expected to fall within the daily ingestion completion time range.
            - Logs confirm whether the last update time is within the specified timeframe.

        Args:
            api_v1_client: API client for interacting with the Lacework API v1.
            wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing a time filter.
        """
        time_filter = wait_for_daily_collection_completion_aws
        start_time = datetime.now(timezone.utc)
        max_wait = 120  # minutes
        query_api = QueryCard(api_v1_client)
        is_within_range = False
        start_time_str = time_filter["startTime"]
        end_time_str = time_filter["endTime"]
        while not is_within_range and (datetime.now(timezone.utc) - start_time) < timedelta(minutes=max_wait):
            response = query_api.get_explorer_last_update()
            assert response.status_code == 200, f"Expected 200 status code but actual {
                response.status_code}"
            response_json = check_and_return_json_from_response(response)
            logger.info(f"Raw response JSON from Explorer API to get last update: {
                        response_json}")
            last_update = response_json['data'][0]['LATEST_END_TIME']
            logger.info(f"Latest collection end time from Explorer API in timestamp (milliseconds): {
                        last_update}")
            last_update_dt_utc = datetime.fromtimestamp(
                last_update/1000, tz=timezone.utc)
            last_update_str = last_update_dt_utc .strftime(
                "%Y-%m-%dT%H:%M:%SZ")
            logger.info(f"Latest collection end time from Explorer API in ISO 8601 standard format: {
                        last_update_str}")
            is_within_range = start_time_str < last_update_str <= end_time_str
            if not is_within_range:
                logger.info(
                    "Sleeping for 60 seconds before retrying to get Explorer's latest update end time.")
                time.sleep(60)

        time_diff = datetime.now(timezone.utc) - start_time
        assert is_within_range, (
            f"Last update time ({
                last_update_str}) is not within the range of the last collection period "
            f"({start_time_str} to {end_time_str}). Additionally, {
                max_wait} minutes have passed since the daily collection was completed."
        )

        # xfail if the update takes more than 1 minute
        if time_diff > timedelta(minutes=1):
            raise TimeoutError(f"Explorer latest update time took more than one minute to update after daily ingestion completion; updated in {
                               time_diff.total_seconds()} seconds.")
        else:
            logger.info(f"Explorer's latest update time was updated within {
                        time_diff.total_seconds()} seconds after ingestion completion.")

    def test_show_all_storage_assets_of_type_aws_accessible_via_identity(self, api_v1_client, e2e_aws_resources, wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws):
        """
        Verify that stored query Show all AWS identities that can access storage assets works as expected

        Given: API V1 Client
        When: Call GraphQL API to simulate the stored query
        Then: Expect status code returned is 200, no Error message returned, and created resources can be found inside response

        Args:
            api_v1_client: API V1 client for interacting with the Lacework
        """
        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type='DATA')
        query.add_filter(key="cloudServiceProvider",
                         operator=ComparisonOperator.IS_IN,
                         value=["AWS"])
        query.add_connector(type="IDENTITY")
        explorer_endtime = datetime.strptime(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['endTime'], "%Y-%m-%dT%H:%M:%SZ")
        one_day_before = explorer_endtime - timedelta(days=1)
        start_timestamp = one_day_before.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_timestamp = explorer_endtime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=start_timestamp, end_time_string=end_timestamp)
        error_messages = ""
        timeout_timestamp = datetime.fromisoformat(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['actual_explorer_update'].replace("Z", "+00:00"))
        timeout_time = timeout_timestamp + timedelta(minutes=30)
        all_found = False
        current_time = timeout_timestamp
        while current_time < timeout_time and not all_found:
            response = graph_api.exec_query(generated_payload)
            response_json = check_and_return_json_from_response(response)
            logger.info(f"Response: {response_json}")
            error_messages = ""
            all_found = True
            for module in iam_user_and_accessible_s3_bucket_tf_modules:
                tf_module = e2e_aws_resources[module]['tf']
                s3_bucket_arn = tf_module.output()['s3_bucket_arn']
                logger.debug(f"Validating ARN: {s3_bucket_arn}")
                found = any(s3_bucket_arn in resource['node']['urn']
                            for resource in response_json['data']['resources']['edges'])
                if not found:
                    error_messages += f"\nFailed to find {
                        s3_bucket_arn} inside Explorer"
                    logger.warning(f"S3 Bucket {s3_bucket_arn} not found")
                    all_found = False
            if not all_found:
                # Update current_time and check remaining time
                current_time = datetime.now(timezone.utc)
                remaining_time = (timeout_time - current_time).total_seconds()
                if remaining_time > 0:
                    logger.debug(f"Remaining time to wait: {
                                 int(remaining_time)} seconds. Sleeping for 60 seconds.")
                    time.sleep(60)
        # Calculate the time difference between curent time and explorer update time
        time_difference_minutes = (datetime.now(
            timezone.utc) - timeout_timestamp).total_seconds() / 60
        if all_found:
            logger.info(f"All S3 bucket validated successfully after {
                        time_difference_minutes:.2f} minutes after explorer update")
        else:
            logger.error(f"Validation failed {
                         time_difference_minutes:.2f} minutes after explorer update")
            raise Exception(f"Validation failed:{error_messages}")

    def test_show_all_aws_identities_that_can_access_storage_assets(self, api_v1_client, e2e_aws_resources, wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws):
        """
        Verify that stored query Show all AWS identities that can access storage assets works as expected

        Given: API V1 Client
        When: Call GraphQL API to simulate the stored query
        Then: Expect status code returned is 200, no Error message returned, and created resources can be found inside response

        Args:
            api_v1_client: API V1 client for interacting with the Lacework
        """
        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type='IDENTITY')
        query.add_filter(key="cloudServiceProvider",
                         operator=ComparisonOperator.IS_IN,
                         value=["AWS"])
        query.add_connector(type="DATA")
        explorer_endtime = datetime.strptime(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['endTime'], "%Y-%m-%dT%H:%M:%SZ")
        one_day_before = explorer_endtime - timedelta(days=1)
        start_timestamp = one_day_before.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_timestamp = explorer_endtime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=start_timestamp, end_time_string=end_timestamp)
        error_messages = ""
        timeout_timestamp = datetime.fromisoformat(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['actual_explorer_update'].replace("Z", "+00:00"))
        timeout_time = timeout_timestamp + timedelta(minutes=30)
        all_found = False
        current_time = timeout_timestamp
        while current_time < timeout_time and not all_found:
            response = graph_api.exec_query(generated_payload)
            response_json = check_and_return_json_from_response(response)
            logger.info(f"Response: {response_json}")
            error_messages = ""
            all_found = True
            for module in iam_user_and_accessible_s3_bucket_tf_modules:
                tf_module = e2e_aws_resources[module]['tf']
                identity_arn = tf_module.output()['iam_user_arn']
                logger.debug(f"Validating ARN: {identity_arn}")
                found = any(identity_arn == resource['node']['urn']
                            for resource in response_json['data']['resources']['edges'])
                if not found:
                    error_messages += f"\nFailed to find {
                        identity_arn} inside Explorer"
                    logger.warning(f"ARN not found: {identity_arn}")
                    all_found = False
            if not all_found:
                # Update current_time and check remaining time
                current_time = datetime.now(timezone.utc)
                remaining_time = (timeout_time - current_time).total_seconds()
                if remaining_time > 0:
                    logger.debug(f"Remaining time to wait: {
                                 int(remaining_time)} seconds. Sleeping for 60 seconds.")
                    time.sleep(60)
        # Calculate the time difference between curent time and explorer update time
        time_difference_minutes = (datetime.now(
            timezone.utc) - timeout_timestamp).total_seconds() / 60
        if all_found:
            logger.info(f"All identity ARNs validated successfully after {
                        time_difference_minutes:.2f} minutes after explorer update")
        else:
            logger.error(f"Validation failed {
                         time_difference_minutes:.2f} minutes after explorer update")
            raise Exception(f"Validation failed:{error_messages}")

    def test_show_deployed_hosts(self, api_v1_client, wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws, e2e_aws_resources):
        """Verify that all instances deployed with terraform before the ingestion are returned by GraphQL.

        Given: API V1 Client
        When: Call GraphQL API to simulate the stored query
        Then: Expect status code returned is 200, no Error message returned, and created resources can be found inside response

        Args:
            api_v1_client: API V1 client for interacting with the Lacework
        """
        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type='COMPUTE')
        explorer_endtime = datetime.strptime(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['endTime'], "%Y-%m-%dT%H:%M:%SZ")
        one_day_before = explorer_endtime - timedelta(days=1)
        start_timestamp = one_day_before.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_timestamp = explorer_endtime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=start_timestamp, end_time_string=end_timestamp)
        error_messages = ""
        timeout_timestamp = datetime.fromisoformat(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['actual_explorer_update'].replace("Z", "+00:00"))
        timeout_time = timeout_timestamp + timedelta(minutes=30)
        all_found = False
        current_time = timeout_timestamp
        while current_time < timeout_time and not all_found:
            response = graph_api.exec_query(generated_payload)
            response_json = check_and_return_json_from_response(response)
            logger.info(f"Response: {response_json}")
            error_messages = ""
            all_found = True
            for module in e2e_aws_resources:
                if 'ec2' in module:
                    tf_module = e2e_aws_resources[module]['tf']
                    output = tf_module.output()
                    instance_id = ""
                    if 'instance_id' in output:
                        instance_id = tf_module.output()['instance_id']
                    else:
                        instance_id = tf_module.output()['instance_id_1']
                    logger.debug(f"Validating host: {instance_id}")
                    found = any(instance_id == resource['node']['resourceId']
                                for resource in response_json['data']['resources']['edges'])
                    if not found:
                        error_messages += f"\nFailed to find {
                            instance_id} inside Explorer"
                        logger.warning(f"EC2 Instance not found: {instance_id}")
                        all_found = False
            if not all_found:
                # Update current_time and check remaining time
                current_time = datetime.now(timezone.utc)
                remaining_time = (timeout_time - current_time).total_seconds()
                if remaining_time > 0:
                    logger.debug(f"Remaining time to wait: {
                                 int(remaining_time)} seconds. Sleeping for 60 seconds.")
                    time.sleep(60)
        # Calculate the time difference between curent time and explorer update time
        time_difference_minutes = (datetime.now(
            timezone.utc) - timeout_timestamp).total_seconds() / 60
        if all_found:
            logger.info(f"All deployed EC2 instances validated successfully after {
                        time_difference_minutes:.2f} minutes after explorer update")
        else:
            logger.error(f"Validation failed {
                         time_difference_minutes:.2f} minutes after explorer update")
            raise Exception(f"Validation failed:{error_messages}")

    def test_show_all_hosts_that_are_internet_exposed_to_a_specific_cidr_range_behind_a_vpn_or_other_gateways(self, api_v1_client, wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws, e2e_aws_resources):
        """
        Verify that stored query Show all hosts that are internet exposed to a specific CIDR range behind a VPN or other gateways

        Given: API V1 Client
        When: Call GraphQL API to simulate the stored query
        Then: Expect status code returned is 200, no Error message returned, and created resources can be found inside response

        Args:
            api_v1_client: API V1 client for interacting with the Lacework
        """
        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type='COMPUTE')
        query.add_filter(key="accessibleFromNetworkRangeV2",
                         operator=ComparisonOperator.IS_ANY_OF,
                         value=["0.0.0.0/0"])
        explorer_endtime = datetime.strptime(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['endTime'], "%Y-%m-%dT%H:%M:%SZ")
        one_day_before = explorer_endtime - timedelta(days=1)
        start_timestamp = one_day_before.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_timestamp = explorer_endtime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=start_timestamp, end_time_string=end_timestamp)
        response = graph_api.exec_query(generated_payload)
        response_json = check_and_return_json_from_response(response)
        logger.info(f"Response: {response_json}")
        tf_module = e2e_aws_resources['ec2_open_to_public']['tf']
        instance_id = tf_module.output()['instance_id']
        timeout_timestamp = datetime.fromisoformat(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['actual_explorer_update'].replace("Z", "+00:00"))
        timeout_time = timeout_timestamp + timedelta(minutes=30)
        found = False
        current_time = timeout_timestamp
        error_messages = ""
        while current_time < timeout_time and not found:
            response = graph_api.exec_query(generated_payload)
            error_messages = ""
            if response.status_code != 200:
                error_messages += f"\nExpected to get status code 200 from GraphQL API, but got err: {
                    response.text}"
            if "errors" in response.json():
                error_messages += f"\nExpect no error returned, but got {
                    response.json()['errors'][0]['message']}"
            if response.elapsed.total_seconds() > 7:
                error_messages += f"\nResponse time: {
                    response.elapsed.total_seconds()} is greater than 7 seconds"
            response_json = check_and_return_json_from_response(response)
            logger.info(f"Response: {response_json}")
            logger.debug(f"Validating EC2: {instance_id}")
            found = any(instance_id in resource['node']['resourceId']
                        for resource in response_json['data']['resources']['edges'])
            if not found:
                # Update current_time and check remaining time
                current_time = datetime.now(timezone.utc)
                remaining_time = (timeout_time - current_time).total_seconds()
                if remaining_time > 0:
                    logger.debug(f"Remaining time to wait: {
                                 int(remaining_time)} seconds. Sleeping for 60 seconds.")
                    time.sleep(60)
        # Calculate the time difference between curent time and explorer update time
        time_difference_minutes = (datetime.now(
            timezone.utc) - timeout_timestamp).total_seconds() / 60
        if not found:
            logger.error(f"Validation failed {
                         time_difference_minutes:.2f} minutes after explorer update")
            error_messages += f"\nFailed to find {instance_id} after {
                time_difference_minutes:.2f} minutes after explorer update"
        else:
            logger.info(f"EC2 instance {instance_id} found after {
                        time_difference_minutes:.2f} minutes after explorer update")
        assert not error_messages, error_messages

    @pytest.mark.parametrize("risk_score", [0])
    def test_show_high_risk_hosts_with_ssh_port_open_and_exposed_to_the_public_internet_due_to_inbound_access(self, risk_score, api_v1_client, wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws, e2e_aws_resources):
        """
        Verify that stored query Show all high risk hosts with ssh port open and exposed to the public internet due to inbound access

        Given: API V1 Client
        When: Call GraphQL API to simulate the stored query
        Then: Expect status code returned is 200, no Error message returned, and created resources can be found inside response

        Args:
            api_v1_client: API V1 client for interacting with the Lacework
        """
        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type='COMPUTE')
        query.add_filter(key="accessibleFromNetworkRangeV2",
                         operator=ComparisonOperator.IS_ANY_OF,
                         value=["0.0.0.0/0"])
        query.add_filter(key="openPortsV2",
                         operator=ComparisonOperator.IS_ANY_OF,
                         value=["22"])
        unifiedEntityRisk_filter = query.add_filter(key="unifiedEntityRisk")
        unifiedEntityRisk_filter.add_subfilter(key="score",
                                               operator=ComparisonOperator.IS_GREATER_THAN_OR_EQUAL_TO,
                                               value=risk_score)
        explorer_endtime = datetime.strptime(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['endTime'], "%Y-%m-%dT%H:%M:%SZ")
        one_day_before = explorer_endtime - timedelta(days=1)
        start_timestamp = one_day_before.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_timestamp = explorer_endtime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=start_timestamp, end_time_string=end_timestamp)
        module = e2e_aws_resources['ec2_open_ssh']['tf']
        instance_id = module.output()['instance_id']
        timeout_timestamp = datetime.fromisoformat(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['actual_explorer_update'].replace("Z", "+00:00"))
        timeout_time = timeout_timestamp + timedelta(minutes=30)
        found = False
        current_time = timeout_timestamp
        error_messages = ""
        while current_time < timeout_time and not found:
            response = graph_api.exec_query(generated_payload)
            error_messages = ""
            if response.status_code != 200:
                error_messages += f"\nExpected to get status code 200 from GraphQL API, but got err: {
                    response.text}"
            if "errors" in response.json():
                error_messages += f"\nExpect no error returned, but got {
                    response.json()['errors'][0]['message']}"
            if response.elapsed.total_seconds() > 7:
                error_messages += f"\nResponse time: {
                    response.elapsed.total_seconds()} is greater than 7 seconds"
            response_json = check_and_return_json_from_response(response)
            logger.info(f"Response: {response_json}")
            logger.debug(f"Validating EC2: {instance_id}")
            found = any(instance_id in resource['node']['resourceId']
                        for resource in response_json['data']['resources']['edges'])
            if not found:
                # Update current_time and check remaining time
                current_time = datetime.now(timezone.utc)
                remaining_time = (timeout_time - current_time).total_seconds()
                if remaining_time > 0:
                    logger.debug(f"Remaining time to wait: {
                                 int(remaining_time)} seconds. Sleeping for 60 seconds.")
                    time.sleep(60)
        # Calculate the time difference between curent time and explorer update time
        time_difference_minutes = (datetime.now(
            timezone.utc) - timeout_timestamp).total_seconds() / 60
        if not found:
            logger.error(f"Validation failed {
                         time_difference_minutes:.2f} minutes after explorer update")
            error_messages += f"\nFailed to find {instance_id} after {
                time_difference_minutes:.2f} minutes after explorer update"
        else:
            logger.info(f"EC2 instance {instance_id} found after {
                        time_difference_minutes:.2f} minutes after explorer update")
        assert not error_messages, error_messages

    def test_show_hosts_with_open_port_is_any_of_22(self, api_v1_client, wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws, e2e_aws_resources):
        """Verify show all hosts with filter openPorts is any of 22

        Given: API V1 Client, Instance with agent installed and sshd process listening on port 22
        When: Call GraphQL API to query hosts where openPorts is any of 22
        Then: Expect status code returned is 200, no Error message returned, and created resources can be found inside response

        Args:
            api_v1_client: API V1 client for interacting with the Lacework
        """
        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type='COMPUTE')
        query.add_filter(key="openPortsV2",
                         operator=ComparisonOperator.IS_ANY_OF,
                         value=["22"])
        explorer_endtime = datetime.strptime(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['endTime'], "%Y-%m-%dT%H:%M:%SZ")
        one_day_before = explorer_endtime - timedelta(days=1)
        start_timestamp = one_day_before.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_timestamp = explorer_endtime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=start_timestamp, end_time_string=end_timestamp)
        module = e2e_aws_resources['ec2_open_to_public']['tf']
        instance_id = module.output()['instance_id']
        timeout_timestamp = datetime.fromisoformat(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['actual_explorer_update'].replace("Z", "+00:00"))
        timeout_time = timeout_timestamp + timedelta(minutes=30)
        found = False
        start_time = time.monotonic()
        time_passed = 0
        current_time = timeout_timestamp
        error_messages = ""
        while current_time < timeout_time and not found:
            response = graph_api.exec_query(generated_payload)
            error_messages = ""
            if response.status_code != 200:
                error_messages += f"\nExpected to get status code 200 from GraphQL API, but got err: {
                    response.text}"
            if "errors" in response.json():
                error_messages += f"\nExpect no error returned, but got {
                    response.json()['errors'][0]['message']}"
            if response.elapsed.total_seconds() > 7:
                error_messages += f"\nResponse time: {
                    response.elapsed.total_seconds()} is greater than 7 seconds"
            response_json = check_and_return_json_from_response(response)
            logger.info(f"Response: {response_json}")
            logger.debug(f"Validating EC2: {instance_id}")
            found = any(instance_id in resource['node']['resourceId']
                        for resource in response_json['data']['resources']['edges'])
            time_passed = int(time.monotonic() - start_time)
            if found:
                logger.info(f"EC2 instance {instance_id}  with open port is any of 22 found after {
                            time_passed / 60} minutes")
            else:
                # Update current_time and check remaining time
                current_time = datetime.now(timezone.utc)
                remaining_time = (timeout_time - current_time).total_seconds()
                if remaining_time > 0:
                    logger.debug(f"Remaining time to wait: {
                                 int(remaining_time)} seconds. Sleeping for 60 seconds.")
                    time.sleep(60)
        if not found:
            logger.error(f"Validation failed after {time_passed / 60} minutes")
            error_messages += f"\nFailed to find {instance_id} with open port is any of 22 after {
                time_passed / 60} minutes"
        assert not error_messages, error_messages

    def test_show_all_hosts_with_log4j_vulnerability(self, api_v1_client, wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws, e2e_aws_resources):
        """Verify that stored query Show all hosts with log4j vulnerability

        Given: API V1 Client, Instance with vulnerable version of log4j jar file downloaded, Agentless integration.
        When: Call GraphQL API to query all hosts with log4j vulnerability.
        Then: Expect status code returned is 200, no Error message returned, and created resources can be found inside response.

        Args:
            api_v1_client: API V1 client for interacting with the Lacework
        """
        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type='COMPUTE')
        vulnerabilities_filter = query.add_filter(key="vulnerabilityFindings")
        vulnerabilities_filter.add_subfilter(key="vulnId",
                                             operator=ComparisonOperator.IS_EQUAL_TO,
                                             value='CVE-2021-44228')
        explorer_endtime = datetime.strptime(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['endTime'], "%Y-%m-%dT%H:%M:%SZ")
        one_day_before = explorer_endtime - timedelta(days=1)
        start_timestamp = one_day_before.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_timestamp = explorer_endtime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=start_timestamp, end_time_string=end_timestamp)
        response = graph_api.exec_query(generated_payload)
        error_messages = ""
        if response.status_code != 200:
            error_messages += f"\nExpected to get status code 200 from GraphQL API, but got err: {
                response.text}"
        if "errors" in response.json():
            error_messages += f"\nExpect no error returned, but got {
                response.json()['errors'][0]['message']}"
        if response.elapsed.total_seconds() > 7:
            error_messages += f"\nResponse time: {
                response.elapsed.total_seconds()} is greater than 7 seconds"
        response_json = check_and_return_json_from_response(response)
        logger.info(f"Response: {response_json}")
        module = e2e_aws_resources['ec2_open_to_public']['tf']
        instance_id = module.output()['instance_id']
        found = False
        for resource in response_json['data']['resources']['edges']:
            if instance_id == resource['node']['resourceId']:
                found = True
                break
        if not found:
            error_messages += f"\nFailed to find {instance_id}"
        assert not error_messages, error_messages

    def test_show_all_that_may_lead_to_lateral_movement_because_of_ssh_keys(self, api_v1_client, wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws, e2e_aws_resources):
        """
        Verify that stored query Show all hosts that may lead to lateral movement because of SSH keys

        Given: API V1 Client
        When: Call GraphQL API to simulate the stored query
        Then: Expect status code returned is 200, no Error message returned, and created resources can be found inside response

        Args:
            api_v1_client: API V1 client for interacting with the Lacework
        """
        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type='COMPUTE')
        query.add_filter(key="hasLateralSshMovement",
                         value=True)
        explorer_endtime = datetime.strptime(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['endTime'], "%Y-%m-%dT%H:%M:%SZ")
        one_day_before = explorer_endtime - timedelta(days=1)
        start_timestamp = one_day_before.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_timestamp = explorer_endtime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=start_timestamp, end_time_string=end_timestamp)
        module = e2e_aws_resources['ec2_lateral_ssh_movement']['tf']
        instance_id_1 = module.output()['instance_id_1']
        instance_id_2 = module.output()['instance_id_2']
        found_instance_1 = False
        found_instance_2 = False
        timeout_timestamp = datetime.fromisoformat(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['actual_explorer_update'].replace("Z", "+00:00"))
        timeout_time = timeout_timestamp + timedelta(minutes=30)
        current_time = timeout_timestamp
        error_messages = ""
        while current_time < timeout_time and not found_instance_1 and not found_instance_2:
            response = graph_api.exec_query(generated_payload)
            error_messages = ""
            if response.status_code != 200:
                error_messages += f"\nExpected to get status code 200 from GraphQL API, but got err: {
                    response.text}"
            if "errors" in response.json():
                error_messages += f"\nExpect no error returned, but got {
                    response.json()['errors'][0]['message']}"
            if response.elapsed.total_seconds() > 7:
                error_messages += f"\nResponse time: {
                    response.elapsed.total_seconds()} is greater than 7 seconds"
            response_json = check_and_return_json_from_response(response)
            logger.info(f"Response: {response_json}")
            logger.debug(f"Validating EC2: {instance_id_1} and {instance_id_2}")
            for resource in response_json['data']['resources']['edges']:
                if instance_id_1 == resource['node']['resourceId']:
                    found_instance_1 = True
                if instance_id_2 == resource['node']['resourceId']:
                    found_instance_2 = True
                if found_instance_1 and found_instance_2:
                    break
            if not found_instance_1 or not found_instance_2:
                # Update current_time and check remaining time
                current_time = datetime.now(timezone.utc)
                remaining_time = (timeout_time - current_time).total_seconds()
                if remaining_time > 0:
                    logger.debug(f"Remaining time to wait: {
                                 int(remaining_time)} seconds. Sleeping for 60 seconds.")
                    time.sleep(60)
        # Calculate the time difference between curent time and explorer update time
        time_difference_minutes = (datetime.now(
            timezone.utc) - timeout_timestamp).total_seconds() / 60
        if found_instance_1 and found_instance_2:
            logger.info(f"EC2 instance {instance_id_1} and {instance_id_2} found after {
                        time_difference_minutes:.2f} minutes after explorer update")

        else:
            logger.error(f"Validation failed {
                         time_difference_minutes:.2f} minutes after explorer update")
            error_messages += f"\nFailed to find {instance_id_1} and {instance_id_2} after {
                time_difference_minutes:.2f} minutes after explorer update"
        assert not error_messages, error_messages

    def test_show_all_hosts_exposed_to_the_internet_and_running_active_packages_with_critical_or_high_severity_vulnerabilities(self, api_v1_client, e2e_aws_resources, wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws):
        """
        Verify that stored query Show all hosts exposed to the internet and running active packages with critical or high severity vulnerabilities

        Given: API V1 Client
        When: Call GraphQL API to simulate the stored query
        Then: Expect status code returned is 200, no Error message returned, and created resources can be found inside response

        Args:
            api_v1_client: API V1 client for interacting with the Lacework
        """
        graph_api = GraphQL(api_v1_client)
        query = GraphQLFilter(type='COMPUTE')
        query.add_filter(key="internetExposed",
                         value="true")
        vulnerabilities_filter = query.add_filter(key="vulnerabilityFindings")
        vulnerabilities_filter.add_subfilter(key="severity",
                                             operator=ComparisonOperator.IS_IN,
                                             value=["CRITICAL", "HIGH"])
        vulnerabilities_filter = query.add_filter(key="vulnerabilityFindings")
        vulnerabilities_filter.add_subfilter(key="packageStatus",
                                             operator=ComparisonOperator.IS_IN,
                                             value=["ACTIVE"])
        explorer_endtime = datetime.strptime(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['endTime'], "%Y-%m-%dT%H:%M:%SZ")
        one_day_before = explorer_endtime - timedelta(days=1)
        start_timestamp = one_day_before.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_timestamp = explorer_endtime.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        generated_payload = GraphQLHelper().generate_payload(
            query, start_time_string=start_timestamp, end_time_string=end_timestamp)
        module = e2e_aws_resources['ec2_internet_expose_with_critical_active_pacakge']['tf']
        instance_id = module.output()['instance_id']
        timeout_timestamp = datetime.fromisoformat(
            wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws['actual_explorer_update'].replace("Z", "+00:00"))
        timeout_time = timeout_timestamp + timedelta(minutes=30)
        found = False
        current_time = timeout_timestamp
        error_messages = ""
        while current_time < timeout_time and not found:
            response = graph_api.exec_query(generated_payload)
            error_messages = ""
            if response.status_code != 200:
                error_messages += f"\nExpected to get status code 200 from GraphQL API, but got err: {
                    response.text}"
            if "errors" in response.json():
                error_messages += f"\nExpect no error returned, but got {
                    response.json()['errors'][0]['message']}"
            if response.elapsed.total_seconds() > 7:
                error_messages += f"\nResponse time: {
                    response.elapsed.total_seconds()} is greater than 7 seconds"
            response_json = check_and_return_json_from_response(response)
            logger.info(f"Response: {response_json}")
            logger.debug(f"Validating EC2: {instance_id}")
            found = any(instance_id in resource['node']['resourceId']
                        for resource in response_json['data']['resources']['edges'])
            if not found:
                # Update current_time and check remaining time
                current_time = datetime.now(timezone.utc)
                remaining_time = (timeout_time - current_time).total_seconds()
                if remaining_time > 0:
                    logger.debug(f"Remaining time to wait: {
                                int(remaining_time)} seconds. Sleeping for 60 seconds.")
                    time.sleep(60)
        # Calculate the time difference between curent time and explorer update time
        time_difference_minutes = (datetime.now(
            timezone.utc) - timeout_timestamp).total_seconds() / 60
        if not found:
            logger.error(f"Validation failed {
                        time_difference_minutes:.2f} minutes after explorer update")
            error_messages += f"\nFailed to find {instance_id} after {
                time_difference_minutes:.2f} minutes after explorer update"
        else:
            logger.info(f"EC2 instance {instance_id} found after {
                        time_difference_minutes:.2f} minutes after explorer update")
        assert not error_messages, error_messages
