import logging
import time
import pytest
from datetime import datetime, timezone, timedelta
from fortiqa.libs.helper.date_helper import timestamp_to_datetime, datetime_to_timestamp
from fortiqa.tests.e2e.ingestion.aws.identity.risk_mappings import AWS_RISKS_MAPPING
logger = logging.getLogger(__name__)


class TestIdentityIAMGroupV1:
    def test_all_deployed_aws_iam_groups_for_identity_exist_in_lacework(
        self,
        all_aws_iam_groups_deployed_for_identity,
        identity_v1_client,
        wait_for_identity_update_post_daily_ingestion_aws,
        aws_account
    ):
        """
        Verify that all AWS IAM groups deployed for identity exist in Lacework.

        Given:
            - A list of IAM groups deployed for identity in AWS.
            - The Lacework API which provides IAM group identity data.
            - A time range corresponding to the daily collection start and end time.

        When:
            - Querying Lacework for IAM groups filtered by AWS account within the given collection time range.

        Then:
            - Validate that all IAM groups deployed in AWS exist in Lacework’s response.

        Args:
            all_aws_iam_groups_deployed_for_identity (list[str]): List of deployed IAM group names in AWS.
            identity_v1_client: Instance of IdentityV1 for making API calls.
            wait_for_identity_update_post_daily_ingestion_aws: Fixture ensuring identity updates post daily ingestion
                collection completion and providing a valid time filter.
            aws_account: Fixture providing AWS account details.
        """
        assert all_aws_iam_groups_deployed_for_identity, "No IAM groups deployed for identity found in terraform output."
        start_time_range = wait_for_identity_update_post_daily_ingestion_aws["start_time_range"]
        end_time_range = wait_for_identity_update_post_daily_ingestion_aws["end_time_range"]
        aws_account_id = aws_account.aws_account_id

        lacework_filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        logger.info(
            f"Querying Lacework for AWS IAM groups for identity in account {aws_account_id} "
            f"within time range: {start_time_range} - {end_time_range}"
        )

        response = identity_v1_client.query_identities(
            start_time_range=start_time_range,
            end_time_range=end_time_range,
            filters=lacework_filters
        )

        assert response.status_code == 200, f"Lacework API query failed: {response.json()}"
        logger.info(f"Lacework API query successful. Response: {response.json()}")

        lacework_group_names = {group["NAME"] for group in response.json().get("data", [])}
        expected_group_names = set(all_aws_iam_groups_deployed_for_identity)
        logger.info(f"Expected AWS IAM group names: {expected_group_names}")

        missing_groups = expected_group_names - lacework_group_names

        assert not missing_groups, (
            f"Missing IAM group names in Lacework: {missing_groups}, expected: {expected_group_names}"
        )

        logger.info(f"All AWS IAM group names for identity found in Lacework. Total: {len(expected_group_names)}")

    def test_all_iam_groups_with_allows_iam_write_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM groups with 'ALLOWS_IAM_WRITE' risk are identified, with retries until a timeout.

    Given:
        - A set of IAM groups with IAM-related policies deployed via Terraform.
        - The identity properties update time range post daily collection completion.
        - The AWS account ID where these groups exist.

    When:
        - The test queries the Lacework API for IAM groups flagged with 'ALLOWS_IAM_WRITE' risk
          within the time range from **daily collection start to identity properties update time**.
        - If the response is unsuccessful or the expected IAM groups are missing, the test retries every 60 seconds
          until the timeout of 20 minutes post identity properties update.
        - Before each retry, the 'end_time_range' is updated to ensure the latest data is queried.

    Then:
        - All deployed IAM groups with IAM-related policies must be present in the API response.
        - The API response must correctly identify these IAM groups as having the 'ALLOWS_IAM_WRITE' risk.
        - Logs elapsed time since identity properties update for both successful and failed attempts.
        - Ensures API is queried dynamically by updating 'end_time_range' before each retry.
        - If the API never returns a successful response (status code 200), the test fails with a clear message.

    Args:
        identity_v1_client: API client fixture for querying identities.
        e2e_aws_resources: Fixture providing Terraform deployment details.
        wait_for_identity_properties_update_post_identity_update_aws: Fixture ensuring identity updates post daily ingestion
            collection completion and providing a valid time filter.
        aws_account: Fixture providing AWS account details."""

        # Extract IAM groups by policy from Terraform output
        iam_group_identity_module = e2e_aws_resources["iam_group_identity"]["tf"]
        iam_groups_by_policy = iam_group_identity_module.output()["iam_groups_by_policy"]

        # Get the list of policies that map to 'ALLOWS_IAM_WRITE' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_IAM_WRITE"]

        # Build a dictionary mapping IAM groups to their assigned policies
        iam_group_to_policies = {}
        for policy in policies_to_check:
            for group in iam_groups_by_policy.get(policy, []):
                iam_group_to_policies.setdefault(group["name"], []).append(policy)

        # Extract IAM group names
        iam_group_names = set(iam_group_to_policies.keys())

        assert iam_group_names, (
            f"No IAM groups with 'ALLOWS_IAM_WRITE' risk are deployed. Expected at least one group with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-GROUPs with 'ALLOWS_IAM_WRITE' risk:\n" +
            "\n".join(
                f"  - {group}: {', '.join(policies)}"
                for group, policies in iam_group_to_policies.items()
            )
        )

        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range
        max_wait_time = timestamp_to_datetime(end_time_range) + timedelta(minutes=20)
        logger.info(f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        aws_account_id = aws_account.aws_account_id

        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_IAM_WRITE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        retry_count = 0
        first_attempt = True
        current_time = datetime.now(timezone.utc)
        while current_time < max_wait_time or first_attempt:
            first_attempt = False
            response = identity_v1_client.query_identities(
                start_time_range, end_time_range, filters)
            if response.status_code == 200:
                response_data = response.json().get("data", [])
                queried_groups = {group["NAME"] for group in response_data}
                elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                missing_groups = iam_group_names - queried_groups
                groups_found_but_missing_property = {
                    group["NAME"]: iam_group_to_policies[group["NAME"]]
                    for group in response_data
                    if group["NAME"] in iam_group_names and "ALLOWS_IAM_WRITE" not in group.get("PROPERTIES", {})
                }

                if not missing_groups and not groups_found_but_missing_property:
                    logger.info(
                        f"All expected IAM groups with 'ALLOWS_IAM_WRITE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated."
                    )
                    return

                if missing_groups:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM groups after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_group_names}\nMissing: {missing_groups}"
                    )

                if groups_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM groups found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_group_names}\nMissing Property: {groups_found_but_missing_property}"
                    )

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds..."
                )

            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(
                f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated. Final status code: {response.status_code}. Response body: {response.text}"
            )

        if missing_groups:
            pytest.fail(
                f"Missing IAM groups in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_group_names}\nMissing: {missing_groups}"
            )

        if groups_found_but_missing_property:
            pytest.fail(
                f"The following IAM groups are missing the expected 'ALLOWS_IAM_WRITE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_group_names}\nMissing Property: {groups_found_but_missing_property}"
            )

    def test_all_iam_groups_with_allows_storage_write_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM groups with 'ALLOWS_STORAGE_WRITE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM groups with Storage-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these groups exist.

        When:
            - The test queries the Lacework API for IAM groups flagged with 'ALLOWS_STORAGE_WRITE' risk
              within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM groups are missing, the test retries every 60 seconds
              until the timeout of 20 minutes post identity properties update.
            - Before each retry, the 'end_time_range' is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM groups with Storage-related policies must be present in the API response.
            - The API response must correctly identify these IAM groups as having the 'ALLOWS_STORAGE_WRITE' risk.
            - Logs elapsed time since identity properties update for both successful and failed attempts.
            - Ensures API is queried dynamically by updating 'end_time_range' before each retry.
            - If the API never returns a successful response (status code 200), the test fails with a clear message.

        Args:
        identity_v1_client: API client fixture for querying identities.
        e2e_aws_resources: Fixture providing Terraform deployment details.
        wait_for_identity_properties_update_post_identity_update_aws: Fixture providing time range and syncing ingestion completion.
        aws_account: Fixture providing AWS account ID.
        """

        iam_group_identity_module = e2e_aws_resources["iam_group_identity"]["tf"]
        iam_groups_by_policy = iam_group_identity_module.output()["iam_groups_by_policy"]

        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_STORAGE_WRITE"]

        iam_group_to_policies = {}
        for policy in policies_to_check:
            for group in iam_groups_by_policy.get(policy, []):
                iam_group_to_policies.setdefault(group["name"], []).append(policy)

        iam_group_names = set(iam_group_to_policies.keys())

        assert iam_group_names, (
            f"No IAM groups with 'ALLOWS_STORAGE_WRITE' risk are deployed. Expected at least one group with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-GROUPs with 'ALLOWS_STORAGE_WRITE' risk:\n" +
            "\n".join(
                f"  - {group}: {', '.join(policies)}"
                for group, policies in iam_group_to_policies.items()
            )
        )

        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range

        max_wait_time = timestamp_to_datetime(end_time_range) + timedelta(minutes=20)
        logger.info(f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        aws_account_id = aws_account.aws_account_id

        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_STORAGE_WRITE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        retry_count = 0
        first_attempt = True
        current_time = datetime.now(timezone.utc)
        while current_time < max_wait_time or first_attempt:
            first_attempt = False
            response = identity_v1_client.query_identities(start_time_range, end_time_range, filters)
            if response.status_code == 200:
                response_data = response.json().get("data", [])
                queried_groups = {group["NAME"] for group in response_data}

                elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                missing_groups = iam_group_names - queried_groups
                groups_found_but_missing_property = {
                    group["NAME"]: iam_group_to_policies[group["NAME"]]
                    for group in response_data
                    if group["NAME"] in iam_group_names and "ALLOWS_STORAGE_WRITE" not in group.get("PROPERTIES", {})
                }

                if not missing_groups and not groups_found_but_missing_property:
                    logger.info(
                        f"All expected IAM groups with 'ALLOWS_STORAGE_WRITE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated."
                    )
                    return

                if missing_groups:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM groups after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_group_names}\nMissing: {missing_groups}"
                    )

                if groups_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM groups found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_group_names}\nMissing Property: {groups_found_but_missing_property}"
                    )

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds..."
                )

            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated. Final status code: {response.status_code}. Response body: {response.text}")

        if missing_groups:
            pytest.fail(
                f"Missing IAM groups in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_group_names}\nMissing: {missing_groups}"
            )

        if groups_found_but_missing_property:
            pytest.fail(
                f"The following IAM groups are missing the expected 'ALLOWS_STORAGE_WRITE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_group_names}\nMissing Property: {groups_found_but_missing_property}"
            )

    def test_all_iam_groups_with_allows_storage_read_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM groups with 'ALLOWS_STORAGE_READ' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM groups with Storage Read-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these groups exist.

        When:
            - The test queries the Lacework API for IAM groups flagged with 'ALLOWS_STORAGE_READ' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM groups are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the 'end_time_range' is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM groups with Storage Read-related policies must be present in the API response.
            - The API response must correctly identify these IAM groups as having the 'ALLOWS_STORAGE_READ' risk.
            - Logs elapsed time since identity properties update for both successful and failed attempts.
            - Ensures API is queried dynamically by updating 'end_time_range' before each retry.
            - If the API never returns a successful response (status code 200), the test fails with a clear message.

        Args:
            identity_v1_client: API client fixture for querying identities.
            e2e_aws_resources: Fixture providing Terraform deployment details.
            wait_for_identity_properties_update_post_identity_update_aws: Fixture ensuring identity updates post daily ingestion
                collection completion and providing a valid time filter.
            aws_account: Fixture providing AWS account details.
        """

        iam_group_identity_module = e2e_aws_resources["iam_group_identity"]["tf"]
        iam_groups_by_policy = iam_group_identity_module.output()["iam_groups_by_policy"]

        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_STORAGE_READ"]

        iam_group_to_policies = {}
        for policy in policies_to_check:
            for group in iam_groups_by_policy.get(policy, []):
                iam_group_to_policies.setdefault(group["name"], []).append(policy)

        iam_group_names = set(iam_group_to_policies.keys())

        assert iam_group_names, (
            f"No IAM groups with 'ALLOWS_STORAGE_READ' risk are deployed. Expected at least one group with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-GROUPs with 'ALLOWS_STORAGE_READ' risk:\n" +
            "\n".join(
                f"  - {group}: {', '.join(policies)}"
                for group, policies in iam_group_to_policies.items()
            )
        )

        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range

        max_wait_time = timestamp_to_datetime(end_time_range) + timedelta(minutes=20)
        logger.info(f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        aws_account_id = aws_account.aws_account_id

        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_STORAGE_READ", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        retry_count = 0
        first_attempt = True
        current_time = datetime.now(timezone.utc)
        while current_time < max_wait_time or first_attempt:
            first_attempt = False
            response = identity_v1_client.query_identities(start_time_range, end_time_range, filters)
            if response.status_code == 200:
                response_data = response.json().get("data", [])
                queried_groups = {group["NAME"] for group in response_data}

                elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                missing_groups = iam_group_names - queried_groups
                groups_found_but_missing_property = {
                    group["NAME"]: iam_group_to_policies[group["NAME"]]
                    for group in response_data
                    if group["NAME"] in iam_group_names and "ALLOWS_STORAGE_READ" not in group.get("PROPERTIES", {})
                }

                if not missing_groups and not groups_found_but_missing_property:
                    logger.info(
                        f"All expected IAM groups with 'ALLOWS_STORAGE_READ' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated."
                    )
                    return

                if missing_groups:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM groups after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes):\nExpected: {iam_group_names}\nMissing: {missing_groups}"
                    )

                if groups_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM groups found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes):\nExpected: {iam_group_names}\nMissing Property: {groups_found_but_missing_property}"
                    )

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds..."
                )

            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(
                f"Test failed after {retry_count} attempts. API call never returned 200 after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes). Status code: {response.status_code}. Response body: {response.text}"
            )

        if missing_groups:
            pytest.fail(
                f"Missing IAM groups in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes):\nExpected: {iam_group_names}\nMissing: {missing_groups}"
            )

        if groups_found_but_missing_property:
            pytest.fail(
                f"The following IAM groups are missing the expected 'ALLOWS_STORAGE_READ' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes):\nExpected: {iam_group_names}\nMissing Property: {groups_found_but_missing_property}"
            )

    def test_all_iam_groups_with_allows_secrets_read_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM groups with 'ALLOWS_SECRETS_READ' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM groups with Secrets Read-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these groups exist.

        When:
            - The test queries the Lacework API for IAM groups flagged with 'ALLOWS_SECRETS_READ' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM groups are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the 'end_time_range' is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM groups with Secrets Read-related policies must be present in the API response.
            - The API response must correctly identify these IAM groups as having the 'ALLOWS_SECRETS_READ' risk.
            - Logs elapsed time since identity properties update for both successful and failed attempts.
            - Ensures API is queried dynamically by updating 'end_time_range' before each retry.
            - If the API never returns a successful response (status code 200), the test fails with a clear message.

        Args:
            identity_v1_client: API client fixture for querying identities.
            e2e_aws_resources: Fixture providing Terraform deployment details.
            wait_for_identity_properties_update_post_identity_update_aws: Fixture ensuring identity updates post daily ingestion
                collection completion and providing a valid time filter.
            aws_account: Fixture providing AWS account details.
        """

        iam_group_identity_module = e2e_aws_resources["iam_group_identity"]["tf"]
        iam_groups_by_policy = iam_group_identity_module.output()["iam_groups_by_policy"]

        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_SECRETS_READ"]

        iam_group_to_policies = {}
        for policy in policies_to_check:
            for group in iam_groups_by_policy.get(policy, []):
                iam_group_to_policies.setdefault(group["name"], []).append(policy)

        iam_group_names = set(iam_group_to_policies.keys())

        assert iam_group_names, (
            f"No IAM groups with 'ALLOWS_SECRETS_READ' risk are deployed. Expected at least one group with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-GROUPs with 'ALLOWS_SECRETS_READ' risk:\n" +
            "\n".join(
                f"  - {group}: {', '.join(policies)}"
                for group, policies in iam_group_to_policies.items()
            )
        )

        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range

        max_wait_time = timestamp_to_datetime(end_time_range) + timedelta(minutes=20)
        logger.info(f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        aws_account_id = aws_account.aws_account_id

        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_SECRETS_READ", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        retry_count = 0
        first_attempt = True
        current_time = datetime.now(timezone.utc)
        while current_time < max_wait_time or first_attempt:
            first_attempt = False
            response = identity_v1_client.query_identities(
                start_time_range, end_time_range, filters)
            if response.status_code == 200:
                response_data = response.json().get("data", [])
                queried_groups = {group["NAME"] for group in response_data}

                elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                missing_groups = iam_group_names - queried_groups
                groups_found_but_missing_property = {
                    group["NAME"]: iam_group_to_policies[group["NAME"]]
                    for group in response_data
                    if group["NAME"] in iam_group_names and "ALLOWS_SECRETS_READ" not in group.get("PROPERTIES", {})
                }

                if not missing_groups and not groups_found_but_missing_property:
                    logger.info(
                        f"All expected IAM groups with 'ALLOWS_SECRETS_READ' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return

                if missing_groups:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM groups after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes):\nExpected: {iam_group_names}\nMissing: {missing_groups}")

                if groups_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM groups found but missing property:\nExpected: {iam_group_names}\nMissing Property: {groups_found_but_missing_property}")

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned 200 after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes). Final status code: {response.status_code}. Response body: {response.text}")

        if missing_groups:
            pytest.fail(f"Missing IAM groups in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes):\nExpected: {iam_group_names}\nMissing: {missing_groups}")

        if groups_found_but_missing_property:
            pytest.fail(f"The following IAM groups are missing the expected 'ALLOWS_SECRETS_READ' property:\nExpected: {iam_group_names}\nMissing Property: {groups_found_but_missing_property}")

    def test_all_iam_groups_with_allows_compute_execute_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM groups with 'ALLOWS_COMPUTE_EXECUTE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM groups with Compute Execute-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these groups exist.

        When:
            - The test queries the Lacework API for IAM groups flagged with 'ALLOWS_COMPUTE_EXECUTE' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM groups are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM groups with Compute Execute-related policies must be present in the API response.
            - The API response must correctly identify these IAM groups as having the 'ALLOWS_COMPUTE_EXECUTE' risk.
            - Logs elapsed time since identity properties update for both successful and failed attempts.
            - Ensures API is queried dynamically by updating 'end_time_range' before each retry.
            - If the API never returns a successful response (status code 200), the test fails with a clear message.

        Args:
            identity_v1_client: API client fixture for querying identities.
            e2e_aws_resources: Fixture providing Terraform deployment details.
            wait_for_identity_properties_update_post_identity_update_aws: Fixture ensuring identity updates post daily ingestion
                collection completion and providing a valid time filter.
            aws_account: Fixture providing AWS account details.
        """

        iam_group_identity_module = e2e_aws_resources["iam_group_identity"]["tf"]
        iam_groups_by_policy = iam_group_identity_module.output()["iam_groups_by_policy"]

        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_COMPUTE_EXECUTE"]

        iam_group_to_policies = {}
        for policy in policies_to_check:
            for group in iam_groups_by_policy.get(policy, []):
                iam_group_to_policies.setdefault(group["name"], []).append(policy)

        iam_group_names = set(iam_group_to_policies.keys())

        assert iam_group_names, (
            f"No IAM groups with 'ALLOWS_COMPUTE_EXECUTE' risk are deployed. Expected at least one group with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-GROUPs with 'ALLOWS_COMPUTE_EXECUTE' risk:\n" +
            "\n".join(
                f"  - {group}: {', '.join(policies)}"
                for group, policies in iam_group_to_policies.items()
            )
        )

        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range

        max_wait_time = timestamp_to_datetime(end_time_range) + timedelta(minutes=20)
        logger.info(f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        aws_account_id = aws_account.aws_account_id

        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_COMPUTE_EXECUTE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        retry_count = 0
        first_attempt = True
        current_time = datetime.now(timezone.utc)
        while current_time < max_wait_time or first_attempt:
            first_attempt = False
            response = identity_v1_client.query_identities(
                start_time_range, end_time_range, filters)
            if response.status_code == 200:
                response_data = response.json().get("data", [])
                queried_groups = {group["NAME"] for group in response_data}

                elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                missing_groups = iam_group_names - queried_groups
                groups_found_but_missing_property = {
                    group["NAME"]: iam_group_to_policies[group["NAME"]]
                    for group in response_data
                    if group["NAME"] in iam_group_names and "ALLOWS_COMPUTE_EXECUTE" not in group.get("PROPERTIES", {})
                }

                if not missing_groups and not groups_found_but_missing_property:
                    logger.info(
                        f"All expected IAM groups with 'ALLOWS_COMPUTE_EXECUTE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                if missing_groups:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM groups after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {missing_groups}\nExpected: {iam_group_names}")

                if groups_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM groups found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {groups_found_but_missing_property}\nExpected: {iam_group_names}")

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(
                f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes). Final status code: {response.status_code}. Response body: {response.text}"
            )

        if missing_groups:
            pytest.fail(
                f"Missing IAM groups in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {missing_groups}\nExpected: {iam_group_names}"
            )

        if groups_found_but_missing_property:
            pytest.fail(
                f"The following IAM groups are missing the expected 'ALLOWS_COMPUTE_EXECUTE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {groups_found_but_missing_property}\nExpected: {iam_group_names}"
            )

    def test_all_iam_groups_with_allows_full_admin_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM groups with 'ALLOWS_FULL_ADMIN' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM groups with Full Admin-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these groups exist.

        When:
            - The test queries the Lacework API for IAM groups flagged with 'ALLOWS_FULL_ADMIN' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM groups are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM groups with Full Admin-related policies must be present in the API response.
            - The API response must correctly identify these IAM groups as having the 'ALLOWS_FULL_ADMIN' risk.
            - Logs elapsed time since identity properties update for both successful and failed attempts.
            - Ensures API is queried dynamically by updating 'end_time_range' before each retry.
            - If the API never returns a successful response (status code 200), the test fails with a clear message.

        Args:
            identity_v1_client: API client fixture for querying identities.
            e2e_aws_resources: Fixture providing Terraform deployment details.
            wait_for_identity_properties_update_post_identity_update_aws: Fixture ensuring identity updates post daily ingestion
                collection completion and providing a valid time filter.
            aws_account: Fixture providing AWS account details.
        """

        iam_group_identity_module = e2e_aws_resources["iam_group_identity"]["tf"]
        iam_groups_by_policy = iam_group_identity_module.output()["iam_groups_by_policy"]

        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_FULL_ADMIN"]

        iam_group_to_policies = {}
        for policy in policies_to_check:
            for group in iam_groups_by_policy.get(policy, []):
                iam_group_to_policies.setdefault(group["name"], []).append(policy)

        iam_group_names = set(iam_group_to_policies.keys())

        assert iam_group_names, (
            f"No IAM groups with 'ALLOWS_FULL_ADMIN' risk are deployed. Expected at least one group with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-GROUPs with 'ALLOWS_FULL_ADMIN' risk:\n" +
            "\n".join(
                f"  - {group}: {', '.join(policies)}"
                for group, policies in iam_group_to_policies.items()
            )
        )

        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range

        max_wait_time = timestamp_to_datetime(end_time_range) + timedelta(minutes=20)
        logger.info(
            f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        aws_account_id = aws_account.aws_account_id

        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_FULL_ADMIN", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        retry_count = 0
        first_attempt = True
        current_time = datetime.now(timezone.utc)
        while current_time < max_wait_time or first_attempt:
            first_attempt = False
            response = identity_v1_client.query_identities(
                start_time_range, end_time_range, filters)
            if response.status_code == 200:
                response_data = response.json().get("data", [])
                queried_groups = {group["NAME"] for group in response_data}

                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                missing_groups = iam_group_names - queried_groups
                groups_found_but_missing_property = {
                    group["NAME"]: iam_group_to_policies[group["NAME"]]
                    for group in response_data
                    if group["NAME"] in iam_group_names and "ALLOWS_FULL_ADMIN" not in group.get("PROPERTIES", {})
                }

                if not missing_groups and not groups_found_but_missing_property:
                    logger.info(
                        f"All expected IAM groups with 'ALLOWS_FULL_ADMIN' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return

                if missing_groups:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM groups after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_groups}\nExpected: {iam_group_names}")

                if groups_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM groups found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {groups_found_but_missing_property}\nExpected: {iam_group_names}")

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes). Final status code: {response.status_code}. Response body: {response.text}")

        if missing_groups:
            pytest.fail(f"Missing IAM groups in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {missing_groups}\nExpected: {iam_group_names}")

        if groups_found_but_missing_property:
            pytest.fail(f"The following IAM groups are missing the expected 'ALLOWS_FULL_ADMIN' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {groups_found_but_missing_property}\nExpected: {iam_group_names}")

    def test_all_iam_groups_with_allows_credential_exposure_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM groups with 'ALLOWS_CREDENTIAL_EXPOSURE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM groups with credential exposure-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these groups exist.

        When:
            - The test queries the Lacework API for IAM groups flagged with 'ALLOWS_CREDENTIAL_EXPOSURE' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM groups are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM groups with credential exposure-related policies must be present in the API response.
            - The API response must correctly identify these IAM groups as having the 'ALLOWS_CREDENTIAL_EXPOSURE' risk.
            - Logs elapsed time since identity properties update for both successful and failed attempts.
            - Ensures API is queried dynamically by updating 'end_time_range' before each retry.
            - If the API never returns a successful response (status code 200), the test fails with a clear message.

        Args:
            identity_v1_client: API client fixture for querying identities.
            e2e_aws_resources: Fixture providing Terraform deployment details.
            wait_for_identity_properties_update_post_identity_update_aws: Fixture ensuring identity updates post daily ingestion
                collection completion and providing a valid time filter.
            aws_account: Fixture providing AWS account details.
        """

        # Extract IAM groups by policy from Terraform output
        iam_group_identity_module = e2e_aws_resources["iam_group_identity"]["tf"]
        iam_groups_by_policy = iam_group_identity_module.output()["iam_groups_by_policy"]

        # Get the list of policies that map to 'ALLOWS_CREDENTIAL_EXPOSURE' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_CREDENTIAL_EXPOSURE"]

        # Build a dictionary mapping IAM groups to their assigned policies
        iam_group_to_policies = {}
        for policy in policies_to_check:
            for group in iam_groups_by_policy.get(policy, []):
                iam_group_to_policies.setdefault(group["name"], []).append(policy)

        # Extract IAM group names
        iam_group_names = set(iam_group_to_policies.keys())

        # Ensure at least one IAM group exists with a relevant policy
        assert iam_group_names, (
            f"No IAM groups with 'ALLOWS_CREDENTIAL_EXPOSURE' risk are deployed. Expected at least one group with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-GROUPs with 'ALLOWS_CREDENTIAL_EXPOSURE' risk:\n" +
            "\n".join(
                f"  - {group}: {', '.join(policies)}"
                for group, policies in iam_group_to_policies.items()
            )
        )

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range

        # Convert end time to datetime and extend timeout by 20 minutes
        max_wait_time = timestamp_to_datetime(end_time_range) + timedelta(minutes=20)
        logger.info(f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        # Get AWS account ID dynamically from the fixture
        aws_account_id = aws_account.aws_account_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_CREDENTIAL_EXPOSURE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        # Retry logic
        retry_count = 0
        first_attempt = True
        current_time = datetime.now(timezone.utc)
        while current_time < max_wait_time or first_attempt:
            first_attempt = False
            response = identity_v1_client.query_identities(
                start_time_range, end_time_range, filters)
            if response.status_code == 200:
                response_data = response.json().get("data", [])
                queried_groups = {group["NAME"] for group in response_data}

                elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                missing_groups = iam_group_names - queried_groups
                groups_found_but_missing_property = {
                    group["NAME"]: iam_group_to_policies[group["NAME"]]
                    for group in response_data
                    if group["NAME"] in iam_group_names and "ALLOWS_CREDENTIAL_EXPOSURE" not in group.get("PROPERTIES", {})
                }

                if not missing_groups and not groups_found_but_missing_property:
                    logger.info(
                        f"All expected IAM groups with 'ALLOWS_CREDENTIAL_EXPOSURE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes).")
                    return  # Test Passes

                if missing_groups:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM groups after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {missing_groups}\nExpected: {iam_group_names}")

                if groups_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM groups found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {groups_found_but_missing_property}\nExpected: {iam_group_names}")
            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        # Final failure reporting
        elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes). Final status code: {response.status_code}. Response body: {response.text}")

        if missing_groups:
            pytest.fail(f"Missing IAM groups in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {missing_groups}\nExpected: {iam_group_names}")

        if groups_found_but_missing_property:
            pytest.fail(f"The following IAM groups are missing the expected 'ALLOWS_CREDENTIAL_EXPOSURE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {groups_found_but_missing_property}\nExpected: {iam_group_names}")

    def test_all_iam_groups_with_allows_resource_exposure_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
     ):
        """Verify that all deployed IAM groups with 'ALLOWS_RESOURCE_EXPOSURE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM groups with resource exposure-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these groups exist.

        When:
            - The test queries the Lacework API for IAM groups flagged with 'ALLOWS_RESOURCE_EXPOSURE' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM groups are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM groups with resource exposure-related policies must be present in the API response.
            - The API response must correctly identify these IAM groups as having the 'ALLOWS_RESOURCE_EXPOSURE' risk.
            - Logs elapsed time since identity properties update for both successful and failed attempts.
            - Ensures API is queried dynamically by updating 'end_time_range' before each retry.
            - If the API never returns a successful response (status code 200), the test fails with a clear message.

        Args:
            identity_v1_client: API client fixture for querying identities.
            e2e_aws_resources: Fixture providing Terraform deployment details.
            wait_for_identity_properties_update_post_identity_update_aws: Fixture ensuring identity updates post daily ingestion
                collection completion and providing a valid time filter.
            aws_account: Fixture providing AWS account details.
        """

        iam_group_identity_module = e2e_aws_resources["iam_group_identity"]["tf"]
        iam_groups_by_policy = iam_group_identity_module.output()["iam_groups_by_policy"]

        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_RESOURCE_EXPOSURE"]

        iam_group_to_policies = {}
        for policy in policies_to_check:
            for group in iam_groups_by_policy.get(policy, []):
                iam_group_to_policies.setdefault(group["name"], []).append(policy)

        iam_group_names = set(iam_group_to_policies.keys())

        assert iam_group_names, (
            f"No IAM groups with 'ALLOWS_RESOURCE_EXPOSURE' risk are deployed. Expected at least one group with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-GROUPs with 'ALLOWS_RESOURCE_EXPOSURE' risk:\n" +
            "\n".join(
                f"  - {group}: {', '.join(policies)}"
                for group, policies in iam_group_to_policies.items()
            )
        )

        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range

        max_wait_time = timestamp_to_datetime(end_time_range) + timedelta(minutes=20)
        logger.info(f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        aws_account_id = aws_account.aws_account_id

        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_RESOURCE_EXPOSURE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        retry_count = 0
        first_attempt = True
        current_time = datetime.now(timezone.utc)
        while current_time < max_wait_time or first_attempt:
            first_attempt = False
            response = identity_v1_client.query_identities(
                start_time_range, end_time_range, filters)
            if response.status_code == 200:
                response_data = response.json().get("data", [])
                queried_groups = {group["NAME"] for group in response_data}

                elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                missing_groups = iam_group_names - queried_groups
                groups_found_but_missing_property = {
                    group["NAME"]: iam_group_to_policies[group["NAME"]]
                    for group in response_data
                    if group["NAME"] in iam_group_names and "ALLOWS_RESOURCE_EXPOSURE" not in group.get("PROPERTIES", {})
                }

                if not missing_groups and not groups_found_but_missing_property:
                    logger.info(
                        f"All expected IAM groups with 'ALLOWS_RESOURCE_EXPOSURE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return

                if missing_groups:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM groups after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_groups}\nExpected: {iam_group_names}")

                if groups_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM groups found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {groups_found_but_missing_property}\nExpected: {iam_group_names}")
            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated. Final status code: {response.status_code}. Response body: {response.text}")

        if missing_groups:
            pytest.fail(f"Missing IAM groups in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_groups}\nExpected: {iam_group_names}")

        if groups_found_but_missing_property:
            pytest.fail(f"The following IAM groups are missing the expected 'ALLOWS_RESOURCE_EXPOSURE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {groups_found_but_missing_property}\nExpected: {iam_group_names}")

    def test_all_iam_groups_with_allows_privilege_passing_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM groups with 'ALLOWS_PRIVILEGE_PASSING' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM groups with privilege-passing-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these groups exist.

        When:
            - The test queries the Lacework API for IAM groups flagged with 'ALLOWS_PRIVILEGE_PASSING' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM groups are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM groups with privilege-passing-related policies must be present in the API response.
            - The API response must correctly identify these IAM groups as having the 'ALLOWS_PRIVILEGE_PASSING' risk.
            - Logs elapsed time since identity properties update for both successful and failed attempts.
            - Ensures API is queried dynamically by updating 'end_time_range' before each retry.
            - If the API never returns a successful response (status code 200), the test fails with a clear message.

        Args:
            identity_v1_client: API client fixture for querying identities.
            e2e_aws_resources: Fixture providing Terraform deployment details.
            wait_for_identity_properties_update_post_identity_update_aws: Fixture ensuring identity updates post daily ingestion
                collection completion and providing a valid time filter.
            aws_account: Fixture providing AWS account details.
        """
        iam_group_identity_module = e2e_aws_resources["iam_group_identity"]["tf"]
        iam_groups_by_policy = iam_group_identity_module.output()["iam_groups_by_policy"]

        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_PRIVILEGE_PASSING"]

        iam_group_to_policies = {}
        for policy in policies_to_check:
            for group in iam_groups_by_policy.get(policy, []):
                iam_group_to_policies.setdefault(group["name"], []).append(policy)

        iam_group_names = set(iam_group_to_policies.keys())
        assert iam_group_names, (
            f"No IAM groups with 'ALLOWS_PRIVILEGE_PASSING' risk are deployed. Expected at least one group with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-GROUPs with 'ALLOWS_PRIVILEGE_PASSING' risk:\n" +
            "\n".join(
                f"  - {group}: {', '.join(policies)}"
                for group, policies in iam_group_to_policies.items()
            )
        )

        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range

        max_wait_time = timestamp_to_datetime(end_time_range) + timedelta(minutes=20)
        logger.info(f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        aws_account_id = aws_account.aws_account_id

        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_PRIVILEGE_PASSING", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        retry_count = 0
        first_attempt = True
        current_time = datetime.now(timezone.utc)
        while current_time < max_wait_time or first_attempt:
            first_attempt = False
            response = identity_v1_client.query_identities(start_time_range, end_time_range, filters)
            if response.status_code == 200:
                response_data = response.json().get("data", [])
                queried_groups = {group["NAME"] for group in response_data}

                elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                missing_groups = iam_group_names - queried_groups
                groups_found_but_missing_property = {
                    group["NAME"]: iam_group_to_policies[group["NAME"]]
                    for group in response_data
                    if group["NAME"] in iam_group_names and "ALLOWS_PRIVILEGE_PASSING" not in group.get("PROPERTIES", {})
                }

                if not missing_groups and not groups_found_but_missing_property:
                    logger.info(
                        f"All expected IAM groups with 'ALLOWS_PRIVILEGE_PASSING' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return

                if missing_groups:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM groups after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {missing_groups}")

                if groups_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM groups found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {groups_found_but_missing_property}")

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes). Final status: {response.status_code}")

        if missing_groups:
            pytest.fail(f"Missing IAM groups after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {missing_groups}")

        if groups_found_but_missing_property:
            pytest.fail(f"Groups missing 'ALLOWS_PRIVILEGE_PASSING' after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes): {groups_found_but_missing_property}")
