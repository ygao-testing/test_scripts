import logging
import pytest
import time
from datetime import datetime, timezone, timedelta
from fortiqa.libs.helper.date_helper import timestamp_to_datetime, datetime_to_timestamp
from fortiqa.tests.e2e.ingestion.aws.identity.risk_mappings import AWS_RISKS_MAPPING
logger = logging.getLogger(__name__)


class TestIdentityIAMRoleV1:
    def test_all_deployed_aws_iam_roles_exist_in_lacework(
        self,
        all_aws_iam_roles,
        identity_v1_client,
        wait_for_identity_update_post_daily_ingestion_aws,
        aws_account
    ):
        """
        Verify that all AWS IAM roles deployed (filtered by 'ingestion_tag' if provided) exist in Lacework.

        Given:
            - A list of IAM roles deployed in AWS.
            - The Lacework API which provides IAM role identity data.
            - A time range corresponding to the daily collection start and end time.

        When:
            - Querying Lacework for IAM roles filtered by AWS account within the given collection time range.

        Then:
            - Validate that all IAM roles from AWS exist in Lacework’s response.

        Args:
            all_aws_iam_roles (list[IAMRole]): List of deployed IAM roles in AWS, filtered by 'ingestion_tag' if provided.
            identity_v1_client: Instance of IdentityV1 for making API calls.
            wait_for_identity_update_post_daily_ingestion_aws: Fixture ensuring identity updates post daily ingestion
            collection completion and providing a valid time filter.
            aws_account: Fixture providing AWS account details.
        """
        assert all_aws_iam_roles, "No IAM roles found in AWS account."

        # Extract time range from fixture (daily collection start and end time)
        start_time_range = wait_for_identity_update_post_daily_ingestion_aws["start_time_range"]
        end_time_range = wait_for_identity_update_post_daily_ingestion_aws["end_time_range"]
        aws_account_id = aws_account.aws_account_id

        # Construct Lacework API filters for IAM roles
        lacework_filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_ROLE", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        # Query Lacework API using correct method signature
        logger.info(f"Querying Lacework for AWS IAM roles in account {aws_account_id} within time range: {start_time_range} - {end_time_range}")
        lacework_response = identity_v1_client.query_identities(
            start_time_range=start_time_range,
            end_time_range=end_time_range,
            filters=lacework_filters
        )

        # Ensure API response status is 200
        assert lacework_response.status_code == 200, f"Lacework API query failed: {lacework_response.json()}"
        logger.info(f"Lacework API query successful. Response: {lacework_response.json()}")

        # Extract only "NAME" from Lacework response data
        lacework_role_names = {role["NAME"] for role in lacework_response.json().get("data", [])}

        # Extract AWS IAM role names from Terraform output
        aws_iam_role_names = {role.role_name for role in all_aws_iam_roles}
        logger.info(f"Expected AWS IAM role names: {aws_iam_role_names}")

        # Compare IAM role names from AWS with Lacework
        # Set difference (roles in AWS but missing in Lacework)
        missing_roles = aws_iam_role_names - lacework_role_names

        assert not missing_roles, f"Missing IAM role names in Lacework: {missing_roles}, expected {aws_iam_role_names}"

        logger.info(f"All AWS IAM role names found in Lacework. Total: {len(aws_iam_role_names)}")

    def test_all_iam_roles_with_allows_iam_write_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM roles with 'ALLOWS_IAM_WRITE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM roles with IAM-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these roles exist.

        When:
            - The test queries the Lacework API for IAM roles flagged with 'ALLOWS_IAM_WRITE' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM roles are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the 'end_time_range' is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM roles with IAM-related policies must be present in the API response.
            - The API response must correctly identify these IAM roles as having the 'ALLOWS_IAM_WRITE' risk.
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

        # Extract IAM roles by policy from Terraform output
        iam_role_identity_module = e2e_aws_resources["iam_role_identity"]["tf"]
        iam_roles_by_policy = iam_role_identity_module.output()["iam_roles_by_policy"]

        # Get the list of policies that map to 'ALLOWS_IAM_WRITE' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_IAM_WRITE"]

        # Build a dictionary mapping IAM roles to their assigned policies
        iam_role_to_policies = {}
        for policy in policies_to_check:
            for role in iam_roles_by_policy.get(policy, []):
                iam_role_to_policies.setdefault(role["name"], []).append(policy)

        # Extract IAM role names
        iam_role_names = set(iam_role_to_policies.keys())

        # Ensure at least one IAM role exists with a relevant policy
        assert iam_role_names, (
            f"No IAM roles with 'ALLOWS_IAM_WRITE' risk are deployed. Expected at least one role with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-ROLEs with 'ALLOWS_IAM_WRITE' risk:\n" +
            "\n".join(
                f"  - {role}: {', '.join(policies)}"
                for role, policies in iam_role_to_policies.items()
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
                {"value": "ALLOWS_IAM_WRITE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_ROLE", "filterGroup": "include"}],
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
                # Parse API response
                response_data = response.json().get("data", [])
                queried_roles = {role["NAME"] for role in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM roles with IAM-related policies appear in the API response
                missing_roles = iam_role_names - queried_roles
                roles_found_but_missing_property = {
                    role["NAME"]: iam_role_to_policies[role["NAME"]]
                    for role in response_data
                    if role["NAME"] in iam_role_names and "ALLOWS_IAM_WRITE" not in role.get("PROPERTIES", {})
                }

                # If no missing roles and all have properties, break the loop
                if not missing_roles and not roles_found_but_missing_property:
                    logger.info(
                        f"All expected IAM roles with 'ALLOWS_IAM_WRITE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated."
                    )
                    return  # Test Passes

                # Log retry reasons
                if missing_roles:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM roles after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing: {missing_roles}"
                    )

                if roles_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM roles found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing Property: {roles_found_but_missing_property}"
                    )

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds..."
                )

            # Check if max wait time is exceeded
            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)  # Retry every 60 seconds
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        # If we reach here, it means the test has failed
        elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(
                f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated. Final status code: {response.status_code}. Response body: {response.text}"
            )

        if missing_roles:
            pytest.fail(
                f"Missing IAM roles in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing: {missing_roles}"
            )

        if roles_found_but_missing_property:
            pytest.fail(
                f"The following IAM roles are missing the expected 'ALLOWS_IAM_WRITE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing Property: {roles_found_but_missing_property}"
            )

    def test_all_iam_roles_with_allows_storage_write_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM roles with 'ALLOWS_STORAGE_WRITE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM roles with Storage-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these roles exist.

        When:
            - The test queries the Lacework API for IAM roles flagged with 'ALLOWS_STORAGE_WRITE' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM roles are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the 'end_time_range' is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM roles with Storage-related policies must be present in the API response.
            - The API response must correctly identify these IAM roles as having the 'ALLOWS_STORAGE_WRITE' risk.
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

        # Extract IAM roles by policy from Terraform output
        iam_role_identity_module = e2e_aws_resources["iam_role_identity"]["tf"]
        iam_roles_by_policy = iam_role_identity_module.output()["iam_roles_by_policy"]

        # Get the list of policies that map to 'ALLOWS_STORAGE_WRITE' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_STORAGE_WRITE"]

        # Build a dictionary mapping IAM roles to their assigned policies
        iam_role_to_policies = {}
        for policy in policies_to_check:
            for role in iam_roles_by_policy.get(policy, []):
                iam_role_to_policies.setdefault(role["name"], []).append(policy)

        # Extract IAM role names
        iam_role_names = set(iam_role_to_policies.keys())

        # Ensure at least one IAM role exists with a relevant policy
        assert iam_role_names, (
            f"No IAM roles with 'ALLOWS_STORAGE_WRITE' risk are deployed. Expected at least one role with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-ROLEs with 'ALLOWS_STORAGE_WRITE' risk:\n" +
            "\n".join(
                f"  - {role}: {', '.join(policies)}"
                for role, policies in iam_role_to_policies.items()
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
                {"value": "ALLOWS_STORAGE_WRITE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_ROLE", "filterGroup": "include"}],
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
                # Parse API response
                response_data = response.json().get("data", [])
                queried_roles = {role["NAME"] for role in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM roles with Storage-related policies appear in the API response
                missing_roles = iam_role_names - queried_roles
                roles_found_but_missing_property = {
                    role["NAME"]: iam_role_to_policies[role["NAME"]]
                    for role in response_data
                    if role["NAME"] in iam_role_names and "ALLOWS_STORAGE_WRITE" not in role.get("PROPERTIES", {})
                }

                # If no missing roles and all have properties, break the loop
                if not missing_roles and not roles_found_but_missing_property:
                    logger.info(
                        f"All expected IAM roles with 'ALLOWS_STORAGE_WRITE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_roles:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM roles after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing: {missing_roles}")

                if roles_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM roles found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing Property: {roles_found_but_missing_property}")

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            # Check if max wait time is exceeded
            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)  # Retry every 60 seconds
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        # If we reach here, it means the test has failed
        elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated. Final status code: {response.status_code}. Response body: {response.text}")

        if missing_roles:
            pytest.fail(
                f"Missing IAM roles in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing: {missing_roles}")

        if roles_found_but_missing_property:
            pytest.fail(
                f"The following IAM roles are missing the expected 'ALLOWS_STORAGE_WRITE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing Property: {roles_found_but_missing_property}")

    def test_all_iam_roles_with_allows_storage_read_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM roles with 'ALLOWS_STORAGE_READ' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM roles with Storage Read-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these roles exist.

        When:
            - The test queries the Lacework API for IAM roles flagged with 'ALLOWS_STORAGE_READ' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM roles are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the 'end_time_range' is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM roles with Storage Read-related policies must be present in the API response.
            - The API response must correctly identify these IAM roles as having the 'ALLOWS_STORAGE_READ' risk.
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

        # Extract IAM roles by policy from Terraform output
        iam_role_identity_module = e2e_aws_resources["iam_role_identity"]["tf"]
        iam_roles_by_policy = iam_role_identity_module.output()["iam_roles_by_policy"]

        # Get the list of policies that map to 'ALLOWS_STORAGE_READ' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_STORAGE_READ"]

        # Build a dictionary mapping IAM roles to their assigned policies
        iam_role_to_policies = {}
        for policy in policies_to_check:
            for role in iam_roles_by_policy.get(policy, []):
                iam_role_to_policies.setdefault(role["name"], []).append(policy)

        # Extract IAM role names
        iam_role_names = set(iam_role_to_policies.keys())

        # Ensure at least one IAM role exists with a relevant policy
        assert iam_role_names, (
            f"No IAM roles with 'ALLOWS_STORAGE_READ' risk are deployed. Expected at least one role with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-ROLEs with 'ALLOWS_STORAGE_READ' risk:\n" +
            "\n".join(
                f"  - {role}: {', '.join(policies)}"
                for role, policies in iam_role_to_policies.items()
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
                {"value": "ALLOWS_STORAGE_READ", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_ROLE", "filterGroup": "include"}],
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
                # Parse API response
                response_data = response.json().get("data", [])
                queried_roles = {role["NAME"] for role in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM roles with Storage Read-related policies appear in the API response
                missing_roles = iam_role_names - queried_roles
                roles_found_but_missing_property = {
                    role["NAME"]: iam_role_to_policies[role["NAME"]]
                    for role in response_data
                    if role["NAME"] in iam_role_names and "ALLOWS_STORAGE_READ" not in role.get("PROPERTIES", {})
                }

                # If no missing roles and all have properties, break the loop
                if not missing_roles and not roles_found_but_missing_property:
                    logger.info(
                        f"All expected IAM roles with 'ALLOWS_STORAGE_READ' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_roles:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM roles after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing: {missing_roles}")

                if roles_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM roles found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing Property: {roles_found_but_missing_property}")

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            # Check if max wait time is exceeded
            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)  # Retry every 60 seconds
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        # If we reach here, it means the test has failed
        elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated. Final status code: {response.status_code}. Response body: {response.text}")

        if missing_roles:
            pytest.fail(
                f"Missing IAM roles in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing: {missing_roles}")

        if roles_found_but_missing_property:
            pytest.fail(
                f"The following IAM roles are missing the expected 'ALLOWS_STORAGE_READ' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing Property: {roles_found_but_missing_property}")

    def test_all_iam_roles_with_allows_secrets_read_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM roles with 'ALLOWS_SECRETS_READ' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM roles with Secrets Read-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these roles exist.

        When:
            - The test queries the Lacework API for IAM roles flagged with 'ALLOWS_SECRETS_READ' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM roles are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the 'end_time_range' is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM roles with Secrets Read-related policies must be present in the API response.
            - The API response must correctly identify these IAM roles as having the 'ALLOWS_SECRETS_READ' risk.
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

        # Extract IAM roles by policy from Terraform output
        iam_role_identity_module = e2e_aws_resources["iam_role_identity"]["tf"]
        iam_roles_by_policy = iam_role_identity_module.output()["iam_roles_by_policy"]

        # Get the list of policies that map to 'ALLOWS_SECRETS_READ' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_SECRETS_READ"]

        # Build a dictionary mapping IAM roles to their assigned policies
        iam_role_to_policies = {}
        for policy in policies_to_check:
            for role in iam_roles_by_policy.get(policy, []):
                iam_role_to_policies.setdefault(role["name"], []).append(policy)

        # Extract IAM role names
        iam_role_names = set(iam_role_to_policies.keys())

        # Ensure at least one IAM role exists with a relevant policy
        assert iam_role_names, (
            f"No IAM roles with 'ALLOWS_SECRETS_READ' risk are deployed. Expected at least one role with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-ROLEs with 'ALLOWS_SECRETS_READ' risk:\n" +
            "\n".join(
                f"  - {role}: {', '.join(policies)}"
                for role, policies in iam_role_to_policies.items()
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
                {"value": "ALLOWS_SECRETS_READ", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_ROLE", "filterGroup": "include"}],
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
                # Parse API response
                response_data = response.json().get("data", [])
                queried_roles = {role["NAME"] for role in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM roles with Secrets Read-related policies appear in the API response
                missing_roles = iam_role_names - queried_roles
                roles_found_but_missing_property = {
                    role["NAME"]: iam_role_to_policies[role["NAME"]]
                    for role in response_data
                    if role["NAME"] in iam_role_names and "ALLOWS_SECRETS_READ" not in role.get("PROPERTIES", {})
                }

                # If no missing roles and all have properties, break the loop
                if not missing_roles and not roles_found_but_missing_property:
                    logger.info(
                        f"All expected IAM roles with 'ALLOWS_SECRETS_READ' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_roles:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM roles after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing: {missing_roles}")

                if roles_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM roles found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing Property: {roles_found_but_missing_property}")

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            # Check if max wait time is exceeded
            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)  # Retry every 60 seconds
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        # If we reach here, it means the test has failed
        elapsed_seconds = (datetime.now(timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated. Final status code: {response.status_code}. Response body: {response.text}")

        if missing_roles:
            pytest.fail(
                f"Missing IAM roles in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing: {missing_roles}")

        if roles_found_but_missing_property:
            pytest.fail(
                f"The following IAM roles are missing the expected 'ALLOWS_SECRETS_READ' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_role_names}\nMissing Property: {roles_found_but_missing_property}")

    def test_all_iam_roles_with_allows_compute_execute_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM roles with 'ALLOWS_COMPUTE_EXECUTE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM roles with Compute Execute-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these roles exist.

        When:
            - The test queries the Lacework API for IAM roles flagged with 'ALLOWS_COMPUTE_EXECUTE' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM roles are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM roles with Compute Execute-related policies must be present in the API response.
            - The API response must correctly identify these IAM roles as having the 'ALLOWS_COMPUTE_EXECUTE' risk.
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

        # Extract IAM roles by policy from Terraform output
        iam_role_identity_module = e2e_aws_resources["iam_role_identity"]["tf"]
        iam_roles_by_policy = iam_role_identity_module.output()["iam_roles_by_policy"]

        # Get the list of policies that map to 'ALLOWS_COMPUTE_EXECUTE' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_COMPUTE_EXECUTE"]

        # Build a dictionary mapping IAM roles to their assigned policies
        iam_role_to_policies = {}
        for policy in policies_to_check:
            for role in iam_roles_by_policy.get(policy, []):
                iam_role_to_policies.setdefault(role["name"], []).append(policy)

        # Extract IAM role names
        iam_role_names = set(iam_role_to_policies.keys())

        # Ensure at least one IAM role exists with a relevant policy
        assert iam_role_names, (
            f"No IAM roles with 'ALLOWS_COMPUTE_EXECUTE' risk are deployed. Expected at least one role with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        # Log IAM roles along with their policies
        logger.info(
            "Expected IAM-ROLE with 'ALLOWS_COMPUTE_EXECUTE' risk:\n" +
            "\n".join(
                f"  - {role}: {', '.join(policies)}"
                for role, policies in iam_role_to_policies.items()
            )
        )

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range

        # Convert end time to datetime and extend timeout by 20 minutes
        max_wait_time = timestamp_to_datetime(
            end_time_range) + timedelta(minutes=20)
        logger.info(
            f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        # Get AWS account ID dynamically from the fixture
        aws_account_id = aws_account.aws_account_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_COMPUTE_EXECUTE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_ROLE", "filterGroup": "include"}],
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
                # Parse API response
                response_data = response.json().get("data", [])
                queried_roles = {role["NAME"] for role in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM roles with Compute Execute-related policies appear in the API response
                missing_roles = iam_role_names - queried_roles
                roles_found_but_missing_property = {
                    role["NAME"]: iam_role_to_policies[role["NAME"]]
                    for role in response_data
                    if role["NAME"] in iam_role_names and "ALLOWS_COMPUTE_EXECUTE" not in role.get("PROPERTIES", {})
                }

                # If no missing roles and all have properties, break the loop
                if not missing_roles and not roles_found_but_missing_property:
                    logger.info(
                        f"All expected IAM roles with 'ALLOWS_COMPUTE_EXECUTE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_roles:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM roles after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_roles}\nExpected: {iam_role_names}")
                    if roles_found_but_missing_property:
                        logger.warning(
                            f"Retry #{retry_count}: IAM roles found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {roles_found_but_missing_property}\nExpected: {iam_role_names}")

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            # Check if max wait time is exceeded
            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)  # Retry every 60 seconds
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        # If we reach here, it means the test has failed
        elapsed_seconds = (datetime.now(
            timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated. Final status code: {response.status_code}. Response body: {response.text}")

        if missing_roles:
            pytest.fail(
                f"Missing IAM roles in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_roles}\nExpected: {iam_role_names}")

        if roles_found_but_missing_property:
            pytest.fail(
                f"The following IAM roles are missing the expected 'ALLOWS_COMPUTE_EXECUTE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {roles_found_but_missing_property}\nExpected: {iam_role_names}")

    def test_all_iam_roles_with_allows_full_admin_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM roles with 'ALLOWS_FULL_ADMIN' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM roles with Full Admin-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these roles exist.

        When:
            - The test queries the Lacework API for IAM roles flagged with 'ALLOWS_FULL_ADMIN' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM roles are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM roles with Full Admin-related policies must be present in the API response.
            - The API response must correctly identify these IAM roles as having the 'ALLOWS_FULL_ADMIN' risk.
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

        # Extract IAM roles by policy from Terraform output
        iam_role_identity_module = e2e_aws_resources["iam_role_identity"]["tf"]
        iam_roles_by_policy = iam_role_identity_module.output()["iam_roles_by_policy"]

        # Get the list of policies that map to 'ALLOWS_FULL_ADMIN' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_FULL_ADMIN"]

        # Build a dictionary mapping IAM roles to their assigned policies
        iam_role_to_policies = {}
        for policy in policies_to_check:
            for role in iam_roles_by_policy.get(policy, []):
                iam_role_to_policies.setdefault(role["name"], []).append(policy)

        # Extract IAM role names
        iam_role_names = set(iam_role_to_policies.keys())

        # Ensure at least one IAM role exists with a relevant policy
        assert iam_role_names, (
            f"No IAM roles with 'ALLOWS_FULL_ADMIN' risk are deployed. Expected at least one role with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        # Log IAM roles along with their policies
        logger.info(
            "Expected IAM-ROLE with 'ALLOWS_FULL_ADMIN' risk:\n" +
            "\n".join(
                f"  - {role}: {', '.join(policies)}"
                for role, policies in iam_role_to_policies.items()
            )
        )

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range

        # Convert end time to datetime and extend timeout by 20 minutes
        max_wait_time = timestamp_to_datetime(
            end_time_range) + timedelta(minutes=20)
        logger.info(
            f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        # Get AWS account ID dynamically from the fixture
        aws_account_id = aws_account.aws_account_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_FULL_ADMIN", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_ROLE", "filterGroup": "include"}],
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
                # Parse API response
                response_data = response.json().get("data", [])
                queried_roles = {role["NAME"] for role in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM roles with Full Admin-related policies appear in the API response
                missing_roles = iam_role_names - queried_roles
                roles_found_but_missing_property = {
                    role["NAME"]: iam_role_to_policies[role["NAME"]]
                    for role in response_data
                    if role["NAME"] in iam_role_names and "ALLOWS_FULL_ADMIN" not in role.get("PROPERTIES", {})
                }

                # If no missing roles and all have properties, break the loop
                if not missing_roles and not roles_found_but_missing_property:
                    logger.info(
                        f"All expected IAM roles with 'ALLOWS_FULL_ADMIN' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_roles:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM roles after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_roles}\nExpected: {iam_role_names}")
                    if roles_found_but_missing_property:
                        logger.warning(
                            f"Retry #{retry_count}: IAM roles found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {roles_found_but_missing_property}\nExpected: {iam_role_names}")

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            # Check if max wait time is exceeded
            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)  # Retry every 60 seconds
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        # If we reach here, it means the test has failed
        elapsed_seconds = (datetime.now(
            timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated. Final status code: {response.status_code}. Response body: {response.text}")

        if missing_roles:
            pytest.fail(
                f"Missing IAM roles in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_roles}\nExpected: {iam_role_names}")

        if roles_found_but_missing_property:
            pytest.fail(
                f"The following IAM roles are missing the expected 'ALLOWS_FULL_ADMIN' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {roles_found_but_missing_property}\nExpected: {iam_role_names}")

    def test_all_iam_roles_with_allows_credential_exposure_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM roles with 'ALLOWS_CREDENTIAL_EXPOSURE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM roles with credential exposure-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these roles exist.

        When:
            - The test queries the Lacework API for IAM roles flagged with 'ALLOWS_CREDENTIAL_EXPOSURE' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM roles are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM roles with credential exposure-related policies must be present in the API response.
            - The API response must correctly identify these IAM roles as having the 'ALLOWS_CREDENTIAL_EXPOSURE' risk.
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

        # Extract IAM roles by policy from Terraform output
        iam_role_identity_module = e2e_aws_resources["iam_role_identity"]["tf"]
        iam_roles_by_policy = iam_role_identity_module.output()["iam_roles_by_policy"]

        # Get the list of policies that map to 'ALLOWS_CREDENTIAL_EXPOSURE' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_CREDENTIAL_EXPOSURE"]

        # Build a dictionary mapping IAM roles to their assigned policies
        iam_role_to_policies = {}
        for policy in policies_to_check:
            for role in iam_roles_by_policy.get(policy, []):
                iam_role_to_policies.setdefault(role["name"], []).append(policy)

        # Extract IAM role names
        iam_role_names = set(iam_role_to_policies.keys())

        # Ensure at least one IAM role exists with a relevant policy
        assert iam_role_names, (
            f"No IAM roles with 'ALLOWS_CREDENTIAL_EXPOSURE' risk are deployed. Expected at least one role with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        # Log IAM roles along with their policies
        logger.info(
            "Expected IAM-ROLEs with 'ALLOWS_CREDENTIAL_EXPOSURE' risk:\n" +
            "\n".join(
                f"  - {role}: {', '.join(policies)}"
                for role, policies in iam_role_to_policies.items()
            )
        )

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range

        # Convert end time to datetime and extend timeout by 20 minutes
        max_wait_time = timestamp_to_datetime(
            end_time_range) + timedelta(minutes=20)
        logger.info(
            f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        # Get AWS account ID dynamically from the fixture
        aws_account_id = aws_account.aws_account_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_CREDENTIAL_EXPOSURE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_ROLE", "filterGroup": "include"}],
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
                # Parse API response
                response_data = response.json().get("data", [])
                queried_roles = {role["NAME"] for role in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM roles with credential exposure-related policies appear in the API response
                missing_roles = iam_role_names - queried_roles
                roles_found_but_missing_property = {
                    role["NAME"]: iam_role_to_policies[role["NAME"]]
                    for role in response_data
                    if role["NAME"] in iam_role_names and "ALLOWS_CREDENTIAL_EXPOSURE" not in role.get("PROPERTIES", {})
                }

                # If no missing roles and all have properties, break the loop
                if not missing_roles and not roles_found_but_missing_property:
                    logger.info(
                        f"All expected IAM roles with 'ALLOWS_CREDENTIAL_EXPOSURE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_roles:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM roles after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_roles}\nExpected: {iam_role_names}")
                    if roles_found_but_missing_property:
                        logger.warning(
                            f"Retry #{retry_count}: IAM roles found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {roles_found_but_missing_property}\nExpected: {iam_role_names}")

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            # Check if max wait time is exceeded
            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)  # Retry every 60 seconds
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        # If we reach here, it means the test has failed
        elapsed_seconds = (datetime.now(
            timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated. Final status code: {response.status_code}. Response body: {response.text}")

        if missing_roles:
            pytest.fail(
                f"Missing IAM roles in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_roles}\nExpected: {iam_role_names}")

        if roles_found_but_missing_property:
            pytest.fail(
                f"The following IAM roles are missing the expected 'ALLOWS_CREDENTIAL_EXPOSURE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {roles_found_but_missing_property}\nExpected: {iam_role_names}")

    def test_all_iam_roles_with_allows_resource_exposure_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM roles with 'ALLOWS_RESOURCE_EXPOSURE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM roles with resource exposure-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these roles exist.

        When:
            - The test queries the Lacework API for IAM roles flagged with 'ALLOWS_RESOURCE_EXPOSURE' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM roles are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM roles with resource exposure-related policies must be present in the API response.
            - The API response must correctly identify these IAM roles as having the 'ALLOWS_RESOURCE_EXPOSURE' risk.
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

        # Extract IAM roles by policy from Terraform output
        iam_role_identity_module = e2e_aws_resources["iam_role_identity"]["tf"]
        iam_roles_by_policy = iam_role_identity_module.output()["iam_roles_by_policy"]

        # Get the list of policies that map to 'ALLOWS_RESOURCE_EXPOSURE' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_RESOURCE_EXPOSURE"]

        # Build a dictionary mapping IAM roles to their assigned policies
        iam_role_to_policies = {}
        for policy in policies_to_check:
            for role in iam_roles_by_policy.get(policy, []):
                iam_role_to_policies.setdefault(role["name"], []).append(policy)

        # Extract IAM role names
        iam_role_names = set(iam_role_to_policies.keys())

        # Ensure at least one IAM role exists with a relevant policy
        assert iam_role_names, (
            f"No IAM roles with 'ALLOWS_RESOURCE_EXPOSURE' risk are deployed. Expected at least one role with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        # Log IAM roles along with their policies
        logger.info(
            "Expected IAM-ROLEs with 'ALLOWS_RESOURCE_EXPOSURE' risk:\n" +
            "\n".join(
                f"  - {role}: {', '.join(policies)}"
                for role, policies in iam_role_to_policies.items()
            )
        )

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range

        # Convert end time to datetime and extend timeout by 20 minutes
        max_wait_time = timestamp_to_datetime(
            end_time_range) + timedelta(minutes=20)
        logger.info(
            f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        # Get AWS account ID dynamically from the fixture
        aws_account_id = aws_account.aws_account_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_RESOURCE_EXPOSURE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_ROLE", "filterGroup": "include"}],
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
                # Parse API response
                response_data = response.json().get("data", [])
                queried_roles = {role["NAME"] for role in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM roles with resource exposure-related policies appear in the API response
                missing_roles = iam_role_names - queried_roles
                roles_found_but_missing_property = {
                    role["NAME"]: iam_role_to_policies[role["NAME"]]
                    for role in response_data
                    if role["NAME"] in iam_role_names and "ALLOWS_RESOURCE_EXPOSURE" not in role.get("PROPERTIES", {})
                }

                # If no missing roles and all have properties, break the loop
                if not missing_roles and not roles_found_but_missing_property:
                    logger.info(
                        f"All expected IAM roles with 'ALLOWS_RESOURCE_EXPOSURE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_roles:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM roles after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_roles}\nExpected: {iam_role_names}")
                    if roles_found_but_missing_property:
                        logger.warning(
                            f"Retry #{retry_count}: IAM roles found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {roles_found_but_missing_property}\nExpected: {iam_role_names}")

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            # Check if max wait time is exceeded
            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)  # Retry every 60 seconds
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        # If we reach here, it means the test has failed
        elapsed_seconds = (datetime.now(
            timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated. Final status code: {response.status_code}. Response body: {response.text}")

        if missing_roles:
            pytest.fail(
                f"Missing IAM roles in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_roles}\nExpected: {iam_role_names}")

        if roles_found_but_missing_property:
            pytest.fail(
                f"The following IAM roles are missing the expected 'ALLOWS_RESOURCE_EXPOSURE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {roles_found_but_missing_property}\nExpected: {iam_role_names}")

    def test_all_iam_roles_with_allows_privilege_passing_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM roles with 'ALLOWS_PRIVILEGE_PASSING' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM roles with privilege-passing-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these roles exist.

        When:
            - The test queries the Lacework API for IAM roles flagged with 'ALLOWS_PRIVILEGE_PASSING' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM roles are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM roles with privilege-passing-related policies must be present in the API response.
            - The API response must correctly identify these IAM roles as having the 'ALLOWS_PRIVILEGE_PASSING' risk.
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

        # Extract IAM roles by policy from Terraform output
        iam_role_identity_module = e2e_aws_resources["iam_role_identity"]["tf"]
        iam_roles_by_policy = iam_role_identity_module.output()["iam_roles_by_policy"]

        # Get the list of policies that map to 'ALLOWS_PRIVILEGE_PASSING' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_PRIVILEGE_PASSING"]

        # Build a dictionary mapping IAM roles to their assigned policies
        iam_role_to_policies = {}
        for policy in policies_to_check:
            for role in iam_roles_by_policy.get(policy, []):
                iam_role_to_policies.setdefault(role["name"], []).append(policy)

        # Extract IAM role names
        iam_role_names = set(iam_role_to_policies.keys())

        # Ensure at least one IAM role exists with a relevant policy
        assert iam_role_names, (
            f"No IAM roles with 'ALLOWS_PRIVILEGE_PASSING' risk are deployed. Expected at least one role with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        # Log IAM roles along with their policies
        logger.info(
            "Expected IAM-ROLEs with 'ALLOWS_PRIVILEGE_PASSING' risk:\n" +
            "\n".join(
                f"  - {role}: {', '.join(policies)}"
                for role, policies in iam_role_to_policies.items()
            )
        )

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        identity_properties_update_time = end_time_range

        # Convert end time to datetime and extend timeout by 20 minutes
        max_wait_time = timestamp_to_datetime(
            end_time_range) + timedelta(minutes=20)
        logger.info(
            f"Timeout for API query set to: {max_wait_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        # Get AWS account ID dynamically from the fixture
        aws_account_id = aws_account.aws_account_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_PRIVILEGE_PASSING", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_ROLE", "filterGroup": "include"}],
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
                # Parse API response
                response_data = response.json().get("data", [])
                queried_roles = {role["NAME"] for role in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM roles with privilege-passing policies appear in the API response
                missing_roles = iam_role_names - queried_roles
                roles_found_but_missing_property = {
                    role["NAME"]: iam_role_to_policies[role["NAME"]]
                    for role in response_data
                    if role["NAME"] in iam_role_names and "ALLOWS_PRIVILEGE_PASSING" not in role.get("PROPERTIES", {})
                }

                # If no missing roles and all have properties, break the loop
                if not missing_roles and not roles_found_but_missing_property:
                    logger.info(
                        f"All expected IAM roles with 'ALLOWS_PRIVILEGE_PASSING' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_roles:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM roles after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_roles}\nExpected: {iam_role_names}")
                    if roles_found_but_missing_property:
                        logger.warning(
                            f"Retry #{retry_count}: IAM roles found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {roles_found_but_missing_property}\nExpected: {iam_role_names}")

            else:
                logger.warning(
                    f"Retry #{retry_count}: API call failed with status code {response.status_code}. Retrying in 60 seconds...")

            # Check if max wait time is exceeded
            current_time = datetime.now(timezone.utc)
            if current_time >= max_wait_time:
                break
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)  # Retry every 60 seconds
            end_time_range = datetime_to_timestamp(current_time)
            retry_count += 1

        # If we reach here, it means the test has failed
        elapsed_seconds = (datetime.now(
            timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
        elapsed_minutes = elapsed_seconds / 60

        if response.status_code != 200:
            pytest.fail(f"Test failed after {retry_count} attempts. API call never returned a 200 status code after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated. Final status code: {response.status_code}. Response body: {response.text}")

        if missing_roles:
            pytest.fail(
                f"Missing IAM roles in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_roles}\nExpected: {iam_role_names}")

        if roles_found_but_missing_property:
            pytest.fail(
                f"The following IAM roles are missing the expected 'ALLOWS_PRIVILEGE_PASSING' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {roles_found_but_missing_property}\nExpected: {iam_role_names}")
