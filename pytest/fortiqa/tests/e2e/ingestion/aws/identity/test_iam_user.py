import logging
import pytest
import time
from datetime import datetime, timezone, timedelta
from fortiqa.libs.helper.date_helper import timestamp_to_datetime, datetime_to_timestamp
from fortiqa.tests.e2e.ingestion.aws.identity.risk_mappings import AWS_RISKS_MAPPING
logger = logging.getLogger(__name__)


class TestIdentityIAMUserV1:

    def test_aws_iam_users_exist_in_lacework(
        self,
        all_aws_iam_users,
        identity_v1_client,
        wait_for_identity_update_post_daily_ingestion_aws, aws_account
    ):
        """
        Verify that all AWS IAM users deployed (filtered by 'ingestion_tag' if provided) exist in Lacework.

        Given:
            - A list of IAM users deployed in AWS.
            - The Lacework API which provides IAM user identity data.
            - A time range corresponding to the daily collection start and end time.

        When:
            - Querying Lacework for IAM users filtered by AWS account within the given collection time range.

        Then:
            - Validate that all IAM users from AWS exist in Lacework’s response.

        Args:
            all_aws_iam_users (list[IAMUser]): List of deployed IAM users in AWS, filtered by 'ingestion_tag' if provided.
            identity_v1_client: Instance of IdentityV1 for making API calls.
            wait_for_identity_update_post_daily_ingestion_aws: Fixture ensuring identity updates post daily ingestion
            collection completion and providing a valid time filter.
            aws_account: Fixture providing AWS account details.
        """
        assert all_aws_iam_users, "No IAM users found in AWS account."
        # Extract time range from fixture (daily collection start and end time)
        start_time_range = wait_for_identity_update_post_daily_ingestion_aws["start_time_range"]
        end_time_range = wait_for_identity_update_post_daily_ingestion_aws["end_time_range"]
        aws_account_id = aws_account.aws_account_id
        # Construct Lacework API filters
        lacework_filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_USER", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        # Query Lacework API using correct method signature
        logger.info(f"Querying Lacework for AWS IAM users in account {
                    aws_account_id} within time range: {start_time_range} - {end_time_range}")
        lacework_response = identity_v1_client.query_identities(
            start_time_range=start_time_range,
            end_time_range=end_time_range,
            filters=lacework_filters
        )

        # Ensure API response status is 200
        assert lacework_response.status_code == 200, f"Lacework API query failed: {
            lacework_response.json()}"
        logger.info(f"Lacework API query successful. Response: {
                    lacework_response.json()}")
        # Extract only "NAME" from Lacework response data
        lacework_user_names = {user["NAME"]
                               for user in lacework_response.json().get("data", [])}

        # Extract AWS IAM user names
        aws_iam_user_names = {user.user_name for user in all_aws_iam_users}
        logger.info(f" Expected AWS IAM user names : {aws_iam_user_names}")

        # Compare IAM user names from AWS with Lacework
        # Set difference (users in AWS but missing in Lacework)
        missing_users = aws_iam_user_names - lacework_user_names

        assert not missing_users, f"Missing IAM user names in Lacework: {
            missing_users} expected {aws_iam_user_names}"

        logger.info(f"All AWS IAM user names found in Lacework. Total: {
                    len(aws_iam_user_names)}")

    def test_filtering_iam_user_by_PRINCIPAL_Id_return_only_iam_user_with_principal_id(
        self,
        random_iam_user,
        identity_v1_client,
        wait_for_identity_update_post_daily_ingestion_aws
    ):
        """Verify that filtering IAM users by PRINCIPAL_ID returns only the IAM user with the specified principal ID (ARN).

        Given:
            - A randomly selected IAM user from the AWS account.
            - The Lacework API which provides IAM user identity data.
            - A time range from daily collection start to **identity update time post ingestion**.

        When:
            - Querying Lacework for IAM users using the PRINCIPAL_ID filter (IAM user ARN).

        Then:
            - Validate that the API response is successful (status code 200).
            - Validate that only the IAM user matching the specified PRINCIPAL_ID appears in the response.

        Args:
            random_iam_user (IAMUser): A randomly selected IAM user from all deployed IAM users.
            identity_v1_client: Instance of IdentityV1 for making API calls.
            wait_for_identity_update_post_daily_ingestion_aws: Fixture ensuring identity updates post daily ingestion
                collection completion and providing a valid time filter.
        """
        if not random_iam_user:
            pytest.skip("Skipping test: No deployed IAM users found.")

        # Extract the IAM user's ARN (Principal ID)
        principal_id = random_iam_user.arn

        # Extract time range from fixture (daily collection start to **identity update time post ingestion**)
        start_time_range = wait_for_identity_update_post_daily_ingestion_aws["start_time_range"]
        # Corrected key reference
        end_time_range = wait_for_identity_update_post_daily_ingestion_aws["end_time_range"]

        # Construct Lacework API filters for PRINCIPAL_ID
        lacework_filters = {
            "CIEM_Identities_Filter.PRINCIPAL_ID": [{"value": principal_id, "filterGroup": "include"}]
        }

        # Query Lacework API
        logger.info(
            f"Querying Lacework for IAM user with PRINCIPAL_ID {principal_id} within time range: {start_time_range} - {end_time_range}")

        lacework_response = identity_v1_client.query_identities(
            start_time_range=start_time_range,
            end_time_range=end_time_range,
            filters=lacework_filters
        )

        # Ensure API response status is 200
        assert lacework_response.status_code == 200, f"Lacework API query failed: {lacework_response.json()}"
        logger.info(
            f"Lacework API query successful. Response: {lacework_response.json()}")

        # Extract returned IAM users
        response_data = lacework_response.json().get("data", [])
        returned_users = {user["NAME"]: user["PRINCIPAL_ID"]
                          for user in response_data}

        # Log queried results
        logger.info(
            f"Queried IAM users with PRINCIPAL_ID filter: {returned_users}")

        # Validate that only the expected IAM user is returned
        assert len(
            returned_users) == 1, f"Expected exactly one IAM user with PRINCIPAL_ID {principal_id}, but got {len(returned_users)} users."
        assert principal_id in returned_users.values(
        ), f"Expected IAM user with PRINCIPAL_ID {principal_id} not found in response."

        logger.info(
            f"Successfully verified that filtering by PRINCIPAL_ID {principal_id} returns only the expected IAM user.")

    def test_filtering_iam_user_by_name_return_only_iam_user_with_name(
        self,
        identity_v1_client,
        random_iam_user,
        wait_for_identity_update_post_daily_ingestion_aws
    ):
        """
        Verify that filtering by IAM user name returns only the expected IAM user.

        Given:
            - A randomly selected IAM user deployed in AWS.
            - The Lacework API which provides IAM user identity data.
            - A time range corresponding to the daily collection start and identity update time.

        When:
            - Querying Lacework for IAM users filtered by name using the IAM user's `user_name`.

        Then:
            - Ensure the response contains only the IAM user matching the specified name.
            - Validate that the API response status is 200.

        Args:
            identity_v1_client: API client fixture for querying identities.
            random_iam_user (IAMUser): A randomly selected IAM user.
            wait_for_identity_update_post_daily_ingestion_aws: Fixture ensuring identity updates post daily ingestion
                and providing a valid time filter.
        """

        # Ensure a valid IAM user is retrieved from the fixture
        if not random_iam_user:
            pytest.skip(
                "No IAM user found in AWS deployment to test filtering by name.")

        iam_user_name = random_iam_user.user_name

        # Extract time range from fixture (daily collection start to identity update time)
        start_time_range = wait_for_identity_update_post_daily_ingestion_aws["start_time_range"]
        end_time_range = wait_for_identity_update_post_daily_ingestion_aws["end_time_range"]

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.NAME": [{"value": iam_user_name, "filterGroup": "include"}]
        }

        # Query Lacework API
        logger.info(
            f"Querying Lacework for IAM user with name '{iam_user_name}' within time range: {start_time_range} - {end_time_range}")
        response = identity_v1_client.query_identities(
            start_time_range=start_time_range,
            end_time_range=end_time_range,
            filters=filters
        )

        # Validate response status
        assert response.status_code == 200, f"API call failed with status code {response.status_code}: {response.text}"

        # Parse API response
        response_data = response.json().get("data", [])

        # Extract IAM user names from API response
        queried_users = {user["NAME"] for user in response_data}

        # Validate response contains only the expected IAM user
        assert queried_users == {iam_user_name}, (
            f"Expected IAM user '{iam_user_name}' in response, but got: {queried_users}"
        )

        logger.info(
            f"Filtering by name '{iam_user_name}' returned the expected IAM user in Lacework.")

    @pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/PSP-3142")
    def test_filtering_iam_user_by_time_range_returns_only_iam_users_within_the_specified_time_range(
        self,
        identity_v1_client,
        wait_for_identity_update_post_daily_ingestion_aws,
        aws_account
    ):
        """
        Verify that filtering by time range returns only IAM users whose 'START_TIME' is within the specified time range.

        Given:
            - The Lacework API provides IAM user identity assessment data.
            - The time range is defined as the daily collection start to the identity update time.
            - The AWS account ID where these users exist.

        When:
            - Querying the Lacework API for IAM users within the specified time range.

        Then:
            - Ensure that all returned IAM users have a 'START_TIME' within the requested time range.
            - Validate that the API response status is 200.

        Args:
            identity_v1_client: API client fixture for querying identities.
            wait_for_identity_update_post_daily_ingestion_aws: Fixture providing daily collection start and identity update time.
            aws_account: Fixture providing AWS account details.
        """

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_update_post_daily_ingestion_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        # Get AWS account ID dynamically from the fixture
        aws_account_id = aws_account.aws_account_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_USER", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        # Query Lacework API
        logger.info(f"Querying Lacework for IAM users within time range: {start_time_range} - {end_time_range}")
        response = identity_v1_client.query_identities(
            start_time_range=start_time_range,
            end_time_range=end_time_range,
            filters=filters
        )

        # Validate response status
        assert response.status_code == 200, f"API call failed with status code {response.status_code}: {response.text}"

        # Parse API response
        response_data = response.json().get("data", [])

        # Ensure all returned users have START_TIME within the expected time range
        users_outside_time_range = {
            user["NAME"]: user["START_TIME"]
            for user in response_data
            if not (start_time_range <= user["START_TIME"] <= end_time_range)
        }

        if users_outside_time_range:
            pytest.fail(
                f"The following IAM users were returned but have a 'START_TIME' outside the requested time range:\n{users_outside_time_range}"
            )

        logger.info("All IAM users returned have 'START_TIME' within the specified time range in Lacework.")

    @pytest.mark.parametrize("risk", AWS_RISKS_MAPPING.keys())
    def test_filtered_iam_user_by_risk_returns_only_iam_users_containing_the_specified_risk(
        self,
        risk,
        identity_v1_client,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """
        Verify that filtering by risk returns only IAM users with the expected risk.

        Given:
            - The Lacework API provides IAM user identity data.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these users exist.

        When:
            - Querying the Lacework API for IAM users filtered by a specific risk.

        Then:
            - Ensure the response contains only IAM users associated with the specified risk.
            - Validate that the API response status is 200.

        Args:
            risk (str): The IAM risk to filter by.
            identity_v1_client: API client fixture for querying identities.
            wait_for_identity_properties_update_post_identity_update_aws: Fixture ensuring identity properties updates post daily ingestion.
            aws_account: Fixture providing AWS account details.
        """

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_properties_update_post_identity_update_aws
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        # Get AWS account ID dynamically from the fixture
        aws_account_id = aws_account.aws_account_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [{"value": risk, "filterGroup": "include"}],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_USER", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": aws_account_id, "filterGroup": "include"}]
        }

        # Query Lacework API
        logger.info(
            f"Querying Lacework for IAM users with '{risk}' risk within time range: {start_time_range} - {end_time_range}")
        response = identity_v1_client.query_identities(
            start_time_range=start_time_range,
            end_time_range=end_time_range,
            filters=filters
        )

        # Validate response status
        assert response.status_code == 200, f"API call failed with status code {response.status_code}: {response.text}"

        # Parse API response
        response_data = response.json().get("data", [])

        # Extract IAM user names from API response
        queried_users = {user["NAME"] for user in response_data}
        logger.info(f"Query response for IAM users with '{risk}' risk: {queried_users}")
        # Ensure all returned users have the expected risk
        users_without_expected_risk = {
            user["NAME"] for user in response_data if risk not in user.get("PROPERTIES", {})
        }

        if users_without_expected_risk:
            pytest.fail(
                f"The following IAM users were returned but do not have the expected '{risk}' property:\n{users_without_expected_risk}"
            )

        logger.info(
            f"All IAM users returned for '{risk}' risk have the expected risk in Lacework.")

    def test_all_iam_users_with_allows_iam_write_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM users with 'ALLOWS_IAM_WRITE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM users with IAM-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these users exist.

        When:
            - The test queries the Lacework API for IAM users flagged with 'ALLOWS_IAM_WRITE' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM users are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the 'end_time_range' is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM users with IAM-related policies must be present in the API response.
            - The API response must correctly identify these IAM users as having the 'ALLOWS_IAM_WRITE' risk.
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

        # Extract IAM users by policy from Terraform output
        iam_user_identity_module = e2e_aws_resources["iam_user_identity"]["tf"]
        iam_users_by_policy = iam_user_identity_module.output()[
            "iam_users_by_policy"]

        # Get the list of policies that map to 'ALLOWS_IAM_WRITE' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_IAM_WRITE"]

        # Build a dictionary mapping IAM users to their assigned policies
        iam_user_to_policies = {}
        for policy in policies_to_check:
            for user in iam_users_by_policy.get(policy, []):
                iam_user_to_policies.setdefault(
                    user["name"], []).append(policy)

        # Extract IAM user names
        iam_user_names = set(iam_user_to_policies.keys())

        # Ensure at least one IAM user exists with a relevant policy
        assert iam_user_names, (
            f"No IAM users with 'ALLOWS_IAM_WRITE' risk are deployed. Expected at least one user with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-USERs with 'ALLOWS_IAM_WRITE' risk:\n" +
            "\n".join(
                f"  - {user}: {', '.join(policies)}"
                for user, policies in iam_user_to_policies.items()
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
                {"value": "ALLOWS_IAM_WRITE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_USER", "filterGroup": "include"}],
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
                queried_users = {user["NAME"] for user in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM users with IAM-related policies appear in the API response
                missing_users = iam_user_names - queried_users
                users_found_but_missing_property = {
                    user["NAME"]: iam_user_to_policies[user["NAME"]]
                    for user in response_data
                    if user["NAME"] in iam_user_names and "ALLOWS_IAM_WRITE" not in user.get("PROPERTIES", {})
                }

                # If no missing users and all have properties, break the loop
                if not missing_users and not users_found_but_missing_property:
                    logger.info(
                        f"All expected IAM users with 'ALLOWS_IAM_WRITE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_users:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM users after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing: {missing_users}")

                if users_found_but_missing_property:
                    logger.warning(f"Retry #{retry_count}: IAM users found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing Property: {users_found_but_missing_property}")

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

        if missing_users:
            pytest.fail(
                f"Missing IAM users in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing: {missing_users}")

        if users_found_but_missing_property:
            pytest.fail(
                f"The following IAM users are missing the expected 'ALLOWS_IAM_WRITE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing Property: {users_found_but_missing_property}")

    def test_all_iam_users_with_allows_storage_write_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM users with 'ALLOWS_STORAGE_WRITE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM users with Storage-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these users exist.

        When:
            - The test queries the Lacework API for IAM users flagged with 'ALLOWS_STORAGE_WRITE' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM users are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the 'end_time_range' is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM users with Storage-related policies must be present in the API response.
            - The API response must correctly identify these IAM users as having the 'ALLOWS_STORAGE_WRITE' risk.
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

        # Extract IAM users by policy from Terraform output
        iam_user_identity_module = e2e_aws_resources["iam_user_identity"]["tf"]
        iam_users_by_policy = iam_user_identity_module.output()[
            "iam_users_by_policy"]

        # Get the list of policies that map to 'ALLOWS_STORAGE_WRITE' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_STORAGE_WRITE"]

        # Build a dictionary mapping IAM users to their assigned policies
        iam_user_to_policies = {}
        for policy in policies_to_check:
            for user in iam_users_by_policy.get(policy, []):
                iam_user_to_policies.setdefault(
                    user["name"], []).append(policy)

        # Extract IAM user names
        iam_user_names = set(iam_user_to_policies.keys())

        # Ensure at least one IAM user exists with a relevant policy
        assert iam_user_names, (
            f"No IAM users with 'ALLOWS_STORAGE_WRITE' risk are deployed. Expected at least one user with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-USERs with 'ALLOWS_STORAGE_WRITE' risk:\n" +
            "\n".join(
                f"  - {user}: {', '.join(policies)}"
                for user, policies in iam_user_to_policies.items()
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
                {"value": "ALLOWS_STORAGE_WRITE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_USER", "filterGroup": "include"}],
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
                queried_users = {user["NAME"] for user in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM users with Storage-related policies appear in the API response
                missing_users = iam_user_names - queried_users
                users_found_but_missing_property = {
                    user["NAME"]: iam_user_to_policies[user["NAME"]]
                    for user in response_data
                    if user["NAME"] in iam_user_names and "ALLOWS_STORAGE_WRITE" not in user.get("PROPERTIES", {})
                }

                # If no missing users and all have properties, break the loop
                if not missing_users and not users_found_but_missing_property:
                    logger.info(
                        f"All expected IAM users with 'ALLOWS_STORAGE_WRITE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_users:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM users after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing: {missing_users}")

                if users_found_but_missing_property:
                    logger.warning(f"Retry #{retry_count}: IAM users found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing Property: {users_found_but_missing_property}")

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

        if missing_users:
            pytest.fail(
                f"Missing IAM users in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing: {missing_users}")

        if users_found_but_missing_property:
            pytest.fail(
                f"The following IAM users are missing the expected 'ALLOWS_STORAGE_WRITE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing Property: {users_found_but_missing_property}")

    def test_all_iam_users_with_allows_storage_read_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM users with 'ALLOWS_STORAGE_READ' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM users with Storage Read-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these users exist.

        When:
            - The test queries the Lacework API for IAM users flagged with 'ALLOWS_STORAGE_READ' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM users are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the 'end_time_range' is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM users with Storage Read-related policies must be present in the API response.
            - The API response must correctly identify these IAM users as having the 'ALLOWS_STORAGE_READ' risk.
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

        # Extract IAM users by policy from Terraform output
        iam_user_identity_module = e2e_aws_resources["iam_user_identity"]["tf"]
        iam_users_by_policy = iam_user_identity_module.output()[
            "iam_users_by_policy"]

        # Get the list of policies that map to 'ALLOWS_STORAGE_READ' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_STORAGE_READ"]

        # Build a dictionary mapping IAM users to their assigned policies
        iam_user_to_policies = {}
        for policy in policies_to_check:
            for user in iam_users_by_policy.get(policy, []):
                iam_user_to_policies.setdefault(
                    user["name"], []).append(policy)

        # Extract IAM user names
        iam_user_names = set(iam_user_to_policies.keys())

        # Ensure at least one IAM user exists with a relevant policy
        assert iam_user_names, (
            f"No IAM users with 'ALLOWS_STORAGE_READ' risk are deployed. Expected at least one user with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-USERs with 'ALLOWS_STORAGE_READ' risk:\n" +
            "\n".join(
                f"  - {user}: {', '.join(policies)}"
                for user, policies in iam_user_to_policies.items()
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
                {"value": "ALLOWS_STORAGE_READ", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_USER", "filterGroup": "include"}],
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
                queried_users = {user["NAME"] for user in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM users with Storage Read-related policies appear in the API response
                missing_users = iam_user_names - queried_users
                users_found_but_missing_property = {
                    user["NAME"]: iam_user_to_policies[user["NAME"]]
                    for user in response_data
                    if user["NAME"] in iam_user_names and "ALLOWS_STORAGE_READ" not in user.get("PROPERTIES", {})
                }

                # If no missing users and all have properties, break the loop
                if not missing_users and not users_found_but_missing_property:
                    logger.info(
                        f"All expected IAM users with 'ALLOWS_STORAGE_READ' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_users:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM users after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing: {missing_users}")

                if users_found_but_missing_property:
                    logger.warning(f"Retry #{retry_count}: IAM users found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing Property: {users_found_but_missing_property}")

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

        if missing_users:
            pytest.fail(
                f"Missing IAM users in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing: {missing_users}")

        if users_found_but_missing_property:
            pytest.fail(
                f"The following IAM users are missing the expected 'ALLOWS_STORAGE_READ' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing Property: {users_found_but_missing_property}")

    def test_all_iam_users_with_allows_secrets_read_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM users with 'ALLOWS_SECRETS_READ' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM users with Secrets Read-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these users exist.

        When:
            - The test queries the Lacework API for IAM users flagged with 'ALLOWS_SECRETS_READ' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM users are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the 'end_time_range' is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM users with Secrets Read-related policies must be present in the API response.
            - The API response must correctly identify these IAM users as having the 'ALLOWS_SECRETS_READ' risk.
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

        # Extract IAM users by policy from Terraform output
        iam_user_identity_module = e2e_aws_resources["iam_user_identity"]["tf"]
        iam_users_by_policy = iam_user_identity_module.output()[
            "iam_users_by_policy"]

        # Get the list of policies that map to 'ALLOWS_SECRETS_READ' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_SECRETS_READ"]

        # Build a dictionary mapping IAM users to their assigned policies
        iam_user_to_policies = {}
        for policy in policies_to_check:
            for user in iam_users_by_policy.get(policy, []):
                iam_user_to_policies.setdefault(
                    user["name"], []).append(policy)

        # Extract IAM user names
        iam_user_names = set(iam_user_to_policies.keys())

        # Ensure at least one IAM user exists with a relevant policy
        assert iam_user_names, (
            f"No IAM users with 'ALLOWS_SECRETS_READ' risk are deployed. Expected at least one user with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        logger.info(
            "Expected IAM-USERs with 'ALLOWS_SECRETS_READ' risk:\n" +
            "\n".join(
                f"  - {user}: {', '.join(policies)}"
                for user, policies in iam_user_to_policies.items()
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
                {"value": "ALLOWS_SECRETS_READ", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_USER", "filterGroup": "include"}],
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
                queried_users = {user["NAME"] for user in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM users with Secrets Read-related policies appear in the API response
                missing_users = iam_user_names - queried_users
                users_found_but_missing_property = {
                    user["NAME"]: iam_user_to_policies[user["NAME"]]
                    for user in response_data
                    if user["NAME"] in iam_user_names and "ALLOWS_SECRETS_READ" not in user.get("PROPERTIES", {})
                }

                # If no missing users and all have properties, break the loop
                if not missing_users and not users_found_but_missing_property:
                    logger.info(
                        f"All expected IAM users with 'ALLOWS_SECRETS_READ' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_users:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM users after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing: {missing_users}")

                if users_found_but_missing_property:
                    logger.warning(f"Retry #{retry_count}: IAM users found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing Property: {users_found_but_missing_property}")

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

        if missing_users:
            pytest.fail(
                f"Missing IAM users in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing: {missing_users}")

        if users_found_but_missing_property:
            pytest.fail(
                f"The following IAM users are missing the expected 'ALLOWS_SECRETS_READ' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated:\nExpected: {iam_user_names}\nMissing Property: {users_found_but_missing_property}")

    def test_all_iam_users_with_allows_compute_execute_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM users with 'ALLOWS_COMPUTE_EXECUTE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM users with Compute Execute-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these users exist.

        When:
            - The test queries the Lacework API for IAM users flagged with 'ALLOWS_COMPUTE_EXECUTE' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM users are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM users with Compute Execute-related policies must be present in the API response.
            - The API response must correctly identify these IAM users as having the 'ALLOWS_COMPUTE_EXECUTE' risk.
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

        # Extract IAM users by policy from Terraform output
        iam_user_identity_module = e2e_aws_resources["iam_user_identity"]["tf"]
        iam_users_by_policy = iam_user_identity_module.output()[
            "iam_users_by_policy"]

        # Get the list of policies that map to 'ALLOWS_COMPUTE_EXECUTE' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_COMPUTE_EXECUTE"]

        # Build a dictionary mapping IAM users to their assigned policies
        iam_user_to_policies = {}
        for policy in policies_to_check:
            for user in iam_users_by_policy.get(policy, []):
                iam_user_to_policies.setdefault(
                    user["name"], []).append(policy)

        # Extract IAM user names
        iam_user_names = set(iam_user_to_policies.keys())

        # Ensure at least one IAM user exists with a relevant policy
        assert iam_user_names, (
            f"No IAM users with 'ALLOWS_COMPUTE_EXECUTE' risk are deployed. Expected at least one user with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        # Log IAM users along with their policies
        logger.info(
            "Expected IAM-USER with 'ALLOWS_COMPUTE_EXECUTE' risk:\n" +
            "\n".join(
                f"  - {user}: {', '.join(policies)}"
                for user, policies in iam_user_to_policies.items()
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
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_USER", "filterGroup": "include"}],
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
                queried_users = {user["NAME"] for user in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM users with Compute Execute-related policies appear in the API response
                missing_users = iam_user_names - queried_users
                users_found_but_missing_property = {
                    user["NAME"]: iam_user_to_policies[user["NAME"]]
                    for user in response_data
                    if user["NAME"] in iam_user_names and "ALLOWS_COMPUTE_EXECUTE" not in user.get("PROPERTIES", {})
                }

                # If no missing users and all have properties, break the loop
                if not missing_users and not users_found_but_missing_property:
                    logger.info(
                        f"All expected IAM users with 'ALLOWS_COMPUTE_EXECUTE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_users:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM users after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_users}\nExpected: {iam_user_names}")
                if users_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM users found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {users_found_but_missing_property}\nExpected: {iam_user_names}")

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

        if missing_users:
            pytest.fail(
                f"Missing IAM users in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_users}\nExpected: {iam_user_names}")

        if users_found_but_missing_property:
            pytest.fail(
                f"The following IAM users are missing the expected 'ALLOWS_COMPUTE_EXECUTE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {users_found_but_missing_property}\nExpected: {iam_user_names}")

    def test_all_iam_users_with_allows_full_admin_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM users with 'ALLOWS_FULL_ADMIN' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM users with Full Admin-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these users exist.

        When:
            - The test queries the Lacework API for IAM users flagged with 'ALLOWS_FULL_ADMIN' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM users are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM users with Full Admin-related policies must be present in the API response.
            - The API response must correctly identify these IAM users as having the 'ALLOWS_FULL_ADMIN' risk.
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

        # Extract IAM users by policy from Terraform output
        iam_user_identity_module = e2e_aws_resources["iam_user_identity"]["tf"]
        iam_users_by_policy = iam_user_identity_module.output()[
            "iam_users_by_policy"]

        # Get the list of policies that map to 'ALLOWS_FULL_ADMIN' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_FULL_ADMIN"]

        # Build a dictionary mapping IAM users to their assigned policies
        iam_user_to_policies = {}
        for policy in policies_to_check:
            for user in iam_users_by_policy.get(policy, []):
                iam_user_to_policies.setdefault(
                    user["name"], []).append(policy)

        # Extract IAM user names
        iam_user_names = set(iam_user_to_policies.keys())

        # Ensure at least one IAM user exists with a relevant policy
        assert iam_user_names, (
            f"No IAM users with 'ALLOWS_FULL_ADMIN' risk are deployed. Expected at least one user with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        # Log IAM users along with their policies
        logger.info(
            "Expected IAM-USER with 'ALLOWS_FULL_ADMIN' risk:\n" +
            "\n".join(
                f"  - {user}: {', '.join(policies)}"
                for user, policies in iam_user_to_policies.items()
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
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_USER", "filterGroup": "include"}],
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
                queried_users = {user["NAME"] for user in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM users with Full Admin-related policies appear in the API response
                missing_users = iam_user_names - queried_users
                users_found_but_missing_property = {
                    user["NAME"]: iam_user_to_policies[user["NAME"]]
                    for user in response_data
                    if user["NAME"] in iam_user_names and "ALLOWS_FULL_ADMIN" not in user.get("PROPERTIES", {})
                }

                # If no missing users and all have properties, break the loop
                if not missing_users and not users_found_but_missing_property:
                    logger.info(
                        f"All expected IAM users with 'ALLOWS_FULL_ADMIN' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_users:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM users after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_users}\nExpected: {iam_user_names}")
                if users_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM users found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {users_found_but_missing_property}\nExpected: {iam_user_names}")

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

        if missing_users:
            pytest.fail(
                f"Missing IAM users in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_users}\nExpected: {iam_user_names}")

        if users_found_but_missing_property:
            pytest.fail(
                f"The following IAM users are missing the expected 'ALLOWS_FULL_ADMIN' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {users_found_but_missing_property}\nExpected: {iam_user_names}")

    def test_all_iam_users_with_allows_credential_exposure_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM users with 'ALLOWS_CREDENTIAL_EXPOSURE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM users with credential exposure-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these users exist.

        When:
            - The test queries the Lacework API for IAM users flagged with 'ALLOWS_CREDENTIAL_EXPOSURE' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM users are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM users with credential exposure-related policies must be present in the API response.
            - The API response must correctly identify these IAM users as having the 'ALLOWS_CREDENTIAL_EXPOSURE' risk.
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

        # Extract IAM users by policy from Terraform output
        iam_user_identity_module = e2e_aws_resources["iam_user_identity"]["tf"]
        iam_users_by_policy = iam_user_identity_module.output()[
            "iam_users_by_policy"]

        # Get the list of policies that map to 'ALLOWS_CREDENTIAL_EXPOSURE' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_CREDENTIAL_EXPOSURE"]

        # Build a dictionary mapping IAM users to their assigned policies
        iam_user_to_policies = {}
        for policy in policies_to_check:
            for user in iam_users_by_policy.get(policy, []):
                iam_user_to_policies.setdefault(
                    user["name"], []).append(policy)

        # Extract IAM user names
        iam_user_names = set(iam_user_to_policies.keys())

        # Ensure at least one IAM user exists with a relevant policy
        assert iam_user_names, (
            f"No IAM users with 'ALLOWS_CREDENTIAL_EXPOSURE' risk are deployed. Expected at least one user with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        # Log IAM users along with their policies
        logger.info(
            "Expected IAM-USERs with 'ALLOWS_CREDENTIAL_EXPOSURE' risk:\n" +
            "\n".join(
                f"  - {user}: {', '.join(policies)}"
                for user, policies in iam_user_to_policies.items()
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
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_USER", "filterGroup": "include"}],
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
                queried_users = {user["NAME"] for user in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM users with credential exposure-related policies appear in the API response
                missing_users = iam_user_names - queried_users
                users_found_but_missing_property = {
                    user["NAME"]: iam_user_to_policies[user["NAME"]]
                    for user in response_data
                    if user["NAME"] in iam_user_names and "ALLOWS_CREDENTIAL_EXPOSURE" not in user.get("PROPERTIES", {})
                }

                # If no missing users and all have properties, break the loop
                if not missing_users and not users_found_but_missing_property:
                    logger.info(
                        f"All expected IAM users with 'ALLOWS_CREDENTIAL_EXPOSURE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_users:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM users after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_users}\nExpected: {iam_user_names}")
                if users_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM users found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {users_found_but_missing_property}\nExpected: {iam_user_names}")

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

        if missing_users:
            pytest.fail(
                f"Missing IAM users in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_users}\nExpected: {iam_user_names}")

        if users_found_but_missing_property:
            pytest.fail(
                f"The following IAM users are missing the expected 'ALLOWS_CREDENTIAL_EXPOSURE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {users_found_but_missing_property}\nExpected: {iam_user_names}")

    def test_all_iam_users_with_allows_resource_exposure_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM users with 'ALLOWS_RESOURCE_EXPOSURE' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM users with resource exposure-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these users exist.

        When:
            - The test queries the Lacework API for IAM users flagged with 'ALLOWS_RESOURCE_EXPOSURE' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM users are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM users with resource exposure-related policies must be present in the API response.
            - The API response must correctly identify these IAM users as having the 'ALLOWS_RESOURCE_EXPOSURE' risk.
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

        # Extract IAM users by policy from Terraform output
        iam_user_identity_module = e2e_aws_resources["iam_user_identity"]["tf"]
        iam_users_by_policy = iam_user_identity_module.output()[
            "iam_users_by_policy"]

        # Get the list of policies that map to 'ALLOWS_RESOURCE_EXPOSURE' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_RESOURCE_EXPOSURE"]

        # Build a dictionary mapping IAM users to their assigned policies
        iam_user_to_policies = {}
        for policy in policies_to_check:
            for user in iam_users_by_policy.get(policy, []):
                iam_user_to_policies.setdefault(
                    user["name"], []).append(policy)

        # Extract IAM user names
        iam_user_names = set(iam_user_to_policies.keys())

        # Ensure at least one IAM user exists with a relevant policy
        assert iam_user_names, (
            f"No IAM users with 'ALLOWS_RESOURCE_EXPOSURE' risk are deployed. Expected at least one user with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        # Log IAM users along with their policies
        logger.info(
            "Expected IAM-USERs with 'ALLOWS_RESOURCE_EXPOSURE' risk:\n" +
            "\n".join(
                f"  - {user}: {', '.join(policies)}"
                for user, policies in iam_user_to_policies.items()
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
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_USER", "filterGroup": "include"}],
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
                queried_users = {user["NAME"] for user in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM users with resource exposure-related policies appear in the API response
                missing_users = iam_user_names - queried_users
                users_found_but_missing_property = {
                    user["NAME"]: iam_user_to_policies[user["NAME"]]
                    for user in response_data
                    if user["NAME"] in iam_user_names and "ALLOWS_RESOURCE_EXPOSURE" not in user.get("PROPERTIES", {})
                }

                # If no missing users and all have properties, break the loop
                if not missing_users and not users_found_but_missing_property:
                    logger.info(
                        f"All expected IAM users with 'ALLOWS_RESOURCE_EXPOSURE' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_users:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM users after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_users}\nExpected: {iam_user_names}")
                if users_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM users found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {users_found_but_missing_property}\nExpected: {iam_user_names}")

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

        if missing_users:
            pytest.fail(
                f"Missing IAM users in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_users}\nExpected: {iam_user_names}")

        if users_found_but_missing_property:
            pytest.fail(
                f"The following IAM users are missing the expected 'ALLOWS_RESOURCE_EXPOSURE' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {users_found_but_missing_property}\nExpected: {iam_user_names}")

    def test_all_iam_users_with_allows_privilege_passing_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM users with 'ALLOWS_PRIVILEGE_PASSING' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM users with privilege-passing-related policies deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these users exist.

        When:
            - The test queries the Lacework API for IAM users flagged with 'ALLOWS_PRIVILEGE_PASSING' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM users are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the `end_time_range` is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM users with privilege-passing-related policies must be present in the API response.
            - The API response must correctly identify these IAM users as having the 'ALLOWS_PRIVILEGE_PASSING' risk.
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

        # Extract IAM users by policy from Terraform output
        iam_user_identity_module = e2e_aws_resources["iam_user_identity"]["tf"]
        iam_users_by_policy = iam_user_identity_module.output()[
            "iam_users_by_policy"]

        # Get the list of policies that map to 'ALLOWS_PRIVILEGE_PASSING' risk
        policies_to_check = AWS_RISKS_MAPPING["ALLOWS_PRIVILEGE_PASSING"]

        # Build a dictionary mapping IAM users to their assigned policies
        iam_user_to_policies = {}
        for policy in policies_to_check:
            for user in iam_users_by_policy.get(policy, []):
                iam_user_to_policies.setdefault(
                    user["name"], []).append(policy)

        # Extract IAM user names
        iam_user_names = set(iam_user_to_policies.keys())

        # Ensure at least one IAM user exists with a relevant policy
        assert iam_user_names, (
            f"No IAM users with 'ALLOWS_PRIVILEGE_PASSING' risk are deployed. Expected at least one user with "
            f"one of these policies: {', '.join(policies_to_check)}"
        )

        # Log IAM users along with their policies
        logger.info(
            "Expected IAM-USERs with 'ALLOWS_PRIVILEGE_PASSING' risk:\n" +
            "\n".join(
                f"  - {user}: {', '.join(policies)}"
                for user, policies in iam_user_to_policies.items()
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
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_USER", "filterGroup": "include"}],
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
                queried_users = {user["NAME"] for user in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM users with privilege-passing policies appear in the API response
                missing_users = iam_user_names - queried_users
                users_found_but_missing_property = {
                    user["NAME"]: iam_user_to_policies[user["NAME"]]
                    for user in response_data
                    if user["NAME"] in iam_user_names and "ALLOWS_PRIVILEGE_PASSING" not in user.get("PROPERTIES", {})
                }

                # If no missing users and all have properties, break the loop
                if not missing_users and not users_found_but_missing_property:
                    logger.info(
                        f"All expected IAM users with 'ALLOWS_PRIVILEGE_PASSING' risk were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_users:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM users after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_users}\nExpected: {iam_user_names}")
                if users_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM users found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {users_found_but_missing_property}\nExpected: {iam_user_names}")

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

        if missing_users:
            pytest.fail(
                f"Missing IAM users in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_users}\nExpected: {iam_user_names}")

        if users_found_but_missing_property:
            pytest.fail(
                f"The following IAM users are missing the expected 'ALLOWS_PRIVILEGE_PASSING' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {users_found_but_missing_property}\nExpected: {iam_user_names}")

    def test_all_iam_users_with_password_login_no_mfa_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_aws_resources,
        wait_for_identity_properties_update_post_identity_update_aws,
        aws_account
    ):
        """Verify that all deployed IAM users with 'PASSWORD_LOGIN_NO_MFA' risk are identified, with retries until a timeout.

        Given:
            - A set of IAM users with console access (No MFA) deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The AWS account ID where these users exist.

        When:
            - The test queries the Lacework API for IAM users flagged with 'PASSWORD_LOGIN_NO_MFA' risk
            within the time range from **daily collection start to identity properties update time**.
            - If the response is unsuccessful or the expected IAM users are missing, the test retries every 60 seconds
            until the timeout of 20 minutes post identity properties update.
            - Before each retry, the 'end_time_range' is updated to ensure the latest data is queried.

        Then:
            - All deployed IAM users with console access must be present in the API response.
            - The API response must correctly identify these IAM users as having the 'PASSWORD_LOGIN_NO_MFA' risk.
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
        # Extract IAM users with console access from Terraform output
        iam_user_identity_module = e2e_aws_resources["iam_user_identity"]["tf"]
        iam_users_by_access = iam_user_identity_module.output()[
            "iam_users_by_access"]
        console_access_users = iam_users_by_access.get("ConsoleAccess", [])

        # Extract IAM user names
        iam_user_names = {user["name"] for user in console_access_users}

        # Ensure that at least one IAM user exists with console access
        assert iam_user_names, "No IAM users with console access found in Terraform deployment."

        logger.info(
            f"Expected IAM-USERs with 'password login no MFA risk': {iam_user_names}")

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
                {"value": "PASSWORD_LOGIN_NO_MFA", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "AWS", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "AWS_USER", "filterGroup": "include"}],
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
                queried_users = {user["NAME"] for user in response_data}

                # Calculate time elapsed since identity properties update
                elapsed_seconds = (datetime.now(
                    timezone.utc) - timestamp_to_datetime(identity_properties_update_time)).total_seconds()
                elapsed_minutes = elapsed_seconds / 60

                # Validate all IAM users with console access appear in the API response
                missing_users = iam_user_names - queried_users
                users_found_but_missing_property = {
                    user["NAME"]
                    for user in response_data
                    if user["NAME"] in iam_user_names and "PASSWORD_LOGIN_NO_MFA" not in user.get("PROPERTIES", {})
                }

                # If no missing users and all have properties, break the loop
                if not missing_users and not users_found_but_missing_property:
                    logger.info(
                        f"All expected IAM users with 'password login no MFA risk' were found in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated.")
                    return  # Test Passes

                # Log retry reasons
                if missing_users:
                    logger.warning(
                        f"Retry #{retry_count}: Missing IAM users after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_users}\nExpected: {iam_user_names}")
                if users_found_but_missing_property:
                    logger.warning(
                        f"Retry #{retry_count}: IAM users found but missing expected property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {users_found_but_missing_property}\nExpected: {iam_user_names}")

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

        if missing_users:
            pytest.fail(
                f"Missing IAM users in Lacework after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {missing_users}\nExpected: {iam_user_names}")

        if users_found_but_missing_property:
            pytest.fail(
                f"The following IAM users are missing the expected 'PASSWORD_LOGIN_NO_MFA' property after {elapsed_seconds:.2f} seconds ({elapsed_minutes:.2f} minutes) post identity properties updated: {users_found_but_missing_property}\nExpected: {iam_user_names}")
