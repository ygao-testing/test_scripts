import logging
import pytest
from fortiqa.libs.lw.apiv1.api_client.identity.identity import IdentityV1
from fortiqa.tests.e2e.ingestion.gcp.identity.risk_mappings import GCP_RISKS_MAPPING, GCP_IAM_TO_ROLE, GCP_USER_ACCOUNT_EMAILS, GCP_GROUP_ACCOUNT_EMAILS
logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def identity_v1_client(api_v1_client):
    """Provides an instance of IdentityV1 to interact with the Lacework Identity API.
    Given:
        - A Lacework API V1 client.
    Returns:
        - An IdentityV1 instance that can be used to make API calls.
    """
    return IdentityV1(api_v1_client)


class TestIdentityGCPUserAccountV1:
    """Test for GCP user accounts and groups"""
    def test_all_deployed_gcp_user_accounts_exist_in_lacework(
        self,
        wait_for_gcp_identity_provider_ingestion,
        identity_v1_client,
        gcp_service_account,
    ):
        """
        Verify that all GCP user accounts deployed exist in Lacework.

        Given:
            - A list of user accounts deployed in GCP.
            - The Lacework API which provides user account identity data.
            - A time range corresponding to the daily collection start and end time.

        When:
            - Querying Lacework for user accounts filtered by GCP project within the given collection time range.

        Then:
            - Validate that all user accounts from GCP exist in Lacework's response.

        Args:
            identity_v1_client: Instance of IdentityV1 for making API calls.
            wait_for_gcp_identity_provider_ingestion: Fixture ensuring identity updates post daily ingestion
            collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP project details.
        """
        # Get ingestion start and end time from fixture
        time_range = wait_for_gcp_identity_provider_ingestion
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        org_name = gcp_service_account.org_name

        # Construct Lacework API filters all types of identities from gcp provider
        lacework_filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_GOOGLE_ACCOUNT", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": org_name, "filterGroup": "include"}]
        }

        # Query Lacework API
        logger.info(f"Querying Lacework for GCP user accounts in organization {org_name}")
        lacework_response = identity_v1_client.query_identities(
            start_time_range=start_time_range,
            end_time_range=end_time_range,
            filters=lacework_filters
        )

        # Ensure API response status is 200
        assert lacework_response.status_code == 200, f"Lacework API query failed: {lacework_response.json()}"
        logger.info(f"Lacework API query successful. Response: {lacework_response.json()}")

        # Extract emails from Lacework response data (which is the unique identifier for user or group accounts)
        lacework_user_account_names = {account["NAME"] for account in lacework_response.json().get("data", [])}
        lacework_principle_ids = {account["PRINCIPAL_ID"] for account in lacework_response.json().get("data", [])}

        # user account is pre-defined and not deployed using terraform
        gcp_user_account_display_names = list(GCP_USER_ACCOUNT_EMAILS.keys())
        gcp_user_account_emails = list(GCP_USER_ACCOUNT_EMAILS.values())

        logger.info(f"Pre-defined GCP user accounts: {gcp_user_account_display_names}")
        # Compare user or group account emails from GCP with Lacework
        missing_account_names = set(gcp_user_account_display_names) - lacework_user_account_names
        missing_principle_ids = set(gcp_user_account_emails) - lacework_principle_ids

        assert not missing_account_names, (
            f"Failed to find all user accounts within timeout period. "
            f"Missing accounts: {missing_account_names}"
        )

        assert not missing_principle_ids, (
            f"Failed to find all user accounts principal ids within timeout period. "
            f"Missing accounts: {missing_principle_ids}"
        )

    def test_all_deployed_gcp_group_accounts_exist_in_lacework(
        self,
        wait_for_gcp_identity_provider_ingestion,
        identity_v1_client,
        gcp_service_account
    ):
        """
        Verify that all GCP group accounts deployed exist in Lacework.

        Given:
            - A list of group accounts deployed in GCP.
            - The Lacework API which provides group account identity data.
            - A time range corresponding to the daily collection start and end time.

        When:
            - Querying Lacework for group accounts filtered by GCP project within the given collection time range.

        Then:
            - Validate that all group accounts from GCP exist in Lacework's response.

        Args:
            identity_v1_client: Instance of IdentityV1 for making API calls.
            wait_for_gcp_identity_provider_ingestion: Fixture ensuring identity updates post daily ingestion
            collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP project details.
        """
        # Get ingestion start and end time from fixture
        time_range = wait_for_gcp_identity_provider_ingestion
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        org_name = gcp_service_account.org_name

        # Construct Lacework API filters for GCP group accounts
        lacework_filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_GOOGLE_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": org_name, "filterGroup": "include"}]
        }

        # Query Lacework API
        logger.info(f"Querying Lacework for GCP group accounts in organization {org_name}")
        lacework_response = identity_v1_client.query_identities(
            start_time_range=start_time_range,
            end_time_range=end_time_range,
            filters=lacework_filters
        )

        # Ensure API response status is 200
        assert lacework_response.status_code == 200, f"Lacework API query failed: {lacework_response.json()}"
        logger.info(f"Lacework API query successful. Response: {lacework_response.json()}")

        # Extract relevant data from Lacework response
        lacework_group_account_names = {account["NAME"] for account in lacework_response.json().get("data", [])}
        lacework_principle_ids = {account["PRINCIPAL_ID"] for account in lacework_response.json().get("data", [])}

        # Group accounts are pre-defined and not deployed using terraform
        gcp_group_account_display_names = list(GCP_GROUP_ACCOUNT_EMAILS.keys())
        gcp_group_account_emails = list(GCP_GROUP_ACCOUNT_EMAILS.values())

        logger.info(f"Expected GCP group accounts: {gcp_group_account_display_names}")

        # Compare group account data from GCP with Lacework
        missing_account_names = set(gcp_group_account_display_names) - lacework_group_account_names
        missing_principle_ids = set(gcp_group_account_emails) - lacework_principle_ids

        assert not missing_account_names, (
            f"Failed to find all group accounts within timeout period. "
            f"Missing accounts: {missing_account_names}"
        )

        assert not missing_principle_ids, (
            f"Failed to find all group accounts principal ids within timeout period. "
            f"Missing accounts: {missing_principle_ids}"
        )

    def test_all_user_or_group_accounts_with_allows_iam_write_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        wait_for_gcp_identity_provider_ingestion,
        gcp_service_account
    ):
        """Verify that all deployed user accounts with 'ALLOWS_IAM_WRITE' risk are identified.

        Given:
            - A set of user accounts with roles related to 'ALLOWS_IAM_WRITE' risk,
            such as owner, storage.admin, cloudfunctions.admin, secretmanager.admin, and compute.admin, deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The GCP organization name where these user accounts exist.

        When:
            - The test queries the Lacework API for user accounts flagged with 'ALLOWS_IAM_WRITE' risk
              within the time range.

        Then:
            - All deployed user accounts with roles related to 'ALLOWS_IAM_WRITE' risk must be present in the API response.
            - The API response must correctly identify these user accounts as having the 'ALLOWS_IAM_WRITE' risk.

        Args:
            identity_v1_client: API client fixture for querying identities.
            wait_for_gcp_identity_provider_ingestion: Fixture ensuring identity updates post daily
            collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP service account details.
        """
        # User accounts with IAM admin role
        gcp_iam_roles = GCP_RISKS_MAPPING["ALLOWS_IAM_WRITE"]
        role_names = []
        for role in gcp_iam_roles:
            role_names.extend(GCP_IAM_TO_ROLE.get(role, []))

        # Collect the emails of user accounts and match with principle id returned from lacework
        user_accounts = []
        for role in role_names:
            if role in GCP_USER_ACCOUNT_EMAILS:
                # pre-defined user or group account
                user_accounts.append(GCP_USER_ACCOUNT_EMAILS.get(role, "Unknown user account"))
            elif role in GCP_GROUP_ACCOUNT_EMAILS:
                # pre-defined group account
                user_accounts.append(GCP_GROUP_ACCOUNT_EMAILS.get(role, "Unknown group account"))

        # Ensure at least one user account exists with a relevant role
        assert user_accounts, "No gcp accounts with 'ALLOWS_IAM_WRITE' risk are deployed."

        logger.info(f"Expected gcp accounts with 'ALLOWS_IAM_WRITE' risk: {user_accounts}")

        # Get ingestion start and end time from fixture
        time_range = wait_for_gcp_identity_provider_ingestion
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        # Get GCP organization name from the fixture
        org_name = gcp_service_account.org_name

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_IAM_WRITE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_GOOGLE_ACCOUNT", "filterGroup": "include"}, {"value": "GCP_GOOGLE_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": org_name, "filterGroup": "include"}]
        }
        response = identity_v1_client.query_identities(
            start_time_range, end_time_range, filters)

        assert response.status_code == 200, f"Lacework API query failed: {response.json()}"
        # Parse API response
        response_data = response.json().get("data", [])
        queried_accounts = {account["PRINCIPAL_ID"] for account in response_data}

        # Validate all gcp accounts with IAM admin roles appear in the API response
        missing_accounts = set(user_accounts) - queried_accounts

        assert not missing_accounts, (
            f"Failed to find all gcp accounts with 'ALLOWS_IAM_WRITE' risk within timeout period. "
            f"Missing accounts: {missing_accounts}"
        )

    def test_all_user_or_group_accounts_with_allows_storage_write_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        wait_for_gcp_identity_provider_ingestion,
        gcp_service_account
    ):
        """Verify that all deployed user or group accounts with 'ALLOWS_STORAGE_WRITE' risk are identified.

        Given:
            - A set of user or group accounts with roles related to 'ALLOWS_STORAGE_WRITE' risk,
            such as Storage Admin, Owner, deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The GCP organization name where these user or group accounts exist.

        When:
            - The test queries the Lacework API for user or group accounts flagged with 'ALLOWS_STORAGE_WRITE' risk
              within the time range.

        Then:
            - All deployed user or group accounts related to 'ALLOWS_STORAGE_WRITE' risk must be present in the API response.
            - The API response must correctly identify these user or group accounts as having the 'ALLOWS_STORAGE_WRITE' risk.

        Args:
            identity_v1_client: API client fixture for querying identities.
            wait_for_gcp_identity_provider_ingestion: Fixture ensuring identity updates post daily
                ingestion collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP service account details.
        """
        # User or group accounts with Storage Admin role
        gcp_iam_roles = GCP_RISKS_MAPPING["ALLOWS_STORAGE_WRITE"]
        role_names = []
        for role in gcp_iam_roles:
            role_names.extend(GCP_IAM_TO_ROLE.get(role, []))

        # Collect the emails of user accounts and match with principle id returned from lacework
        storage_admin_accounts = []
        for role in role_names:
            if role in GCP_USER_ACCOUNT_EMAILS:
                # pre-defined user or group account
                storage_admin_accounts.append(GCP_USER_ACCOUNT_EMAILS.get(role, "Unknown user account"))
            elif role in GCP_GROUP_ACCOUNT_EMAILS:
                # pre-defined group account
                storage_admin_accounts.append(GCP_GROUP_ACCOUNT_EMAILS.get(role, "Unknown group account"))

        # Ensure at least one user or group account exists with a relevant role
        assert storage_admin_accounts, "No user or group accounts with 'ALLOWS_STORAGE_WRITE' risk are deployed."

        logger.info(f"Expected user or group accounts with 'ALLOWS_STORAGE_WRITE' risk: {storage_admin_accounts}")

        # Get ingestion start and end time from fixture
        time_range = wait_for_gcp_identity_provider_ingestion
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        # Get GCP organization name from the fixture
        org_name = gcp_service_account.org_name

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_STORAGE_WRITE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_GOOGLE_ACCOUNT", "filterGroup": "include"}, {"value": "GCP_GOOGLE_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": org_name, "filterGroup": "include"}]
        }

        response = identity_v1_client.query_identities(
            start_time_range, end_time_range, filters)

        assert response.status_code == 200, f"Failed to query identities: {response.text}"

        # Parse API response
        response_data = response.json().get("data", [])
        queried_accounts = {account["PRINCIPAL_ID"] for account in response_data}

        # Validate all user or group accounts with Storage Admin roles appear in the API response
        missing_accounts = set(storage_admin_accounts) - queried_accounts

        assert not missing_accounts, (
            f"Failed to find all user or group accounts with 'ALLOWS_STORAGE_WRITE' risk within timeout period. "
            f"Missing accounts: {missing_accounts}"
        )

    def test_all_user_or_group_accounts_with_allows_compute_execute_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        wait_for_gcp_identity_provider_ingestion,
        gcp_service_account
    ):
        """Verify that all deployed user or group accounts with 'ALLOWS_COMPUTE_EXECUTE' risk are identified.

        Given:
            - A set of user or group accounts with roles related to 'ALLOWS_COMPUTE_EXECUTE' risk,
            such as Compute Admin, Cloud Functions Admin, Owner, deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The GCP organization name where these user or group accounts exist.

        When:
            - The test queries the Lacework API for user or group accounts flagged with 'ALLOWS_COMPUTE_EXECUTE' risk within the time range.

        Then:
            - All deployed user or group accounts with 'ALLOWS_COMPUTE_EXECUTE' risk must be present in the API response.
            - The API response must correctly identify these user or group accounts as having the 'ALLOWS_COMPUTE_EXECUTE' risk.

        Args:
            identity_v1_client: API client fixture for querying identities.
            wait_for_gcp_identity_provider_ingestion: Fixture ensuring identity updates post daily
                ingestion collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP service account details.
        """
        # User or group accounts with Compute execution permissions
        gcp_iam_roles = GCP_RISKS_MAPPING["ALLOWS_COMPUTE_EXECUTE"]
        role_names = []
        for role in gcp_iam_roles:
            role_names.extend(GCP_IAM_TO_ROLE.get(role, []))

        # Collect the emails of user accounts and match with principle id returned from lacework
        compute_execute_accounts = []
        for role in role_names:
            if role in GCP_USER_ACCOUNT_EMAILS:
                # pre-defined user or group account
                compute_execute_accounts.append(GCP_USER_ACCOUNT_EMAILS.get(role, "Unknown user account"))
            elif role in GCP_GROUP_ACCOUNT_EMAILS:
                # pre-defined group account
                compute_execute_accounts.append(GCP_GROUP_ACCOUNT_EMAILS.get(role, "Unknown group account"))

        # Ensure at least one user or group account exists with a relevant role
        assert compute_execute_accounts, "No user or group accounts with 'ALLOWS_COMPUTE_EXECUTE' risk are deployed."

        logger.info(f"Expected user or group accounts with 'ALLOWS_COMPUTE_EXECUTE' risk: {compute_execute_accounts}")

        # Get ingestion start and end time from fixture
        time_range = wait_for_gcp_identity_provider_ingestion
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        # Get GCP organization name from the fixture
        org_name = gcp_service_account.org_name

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_COMPUTE_EXECUTE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_GOOGLE_ACCOUNT", "filterGroup": "include"}, {"value": "GCP_GOOGLE_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": org_name, "filterGroup": "include"}]
        }

        response = identity_v1_client.query_identities(
            start_time_range, end_time_range, filters)

        assert response.status_code == 200, f"Failed to query identities: {response.text}"
        # Parse API response
        response_data = response.json().get("data", [])
        queried_accounts = {account["PRINCIPAL_ID"] for account in response_data}

        # Validate all user or group accounts with compute execution permissions appear in the API response
        missing_accounts = set(compute_execute_accounts) - queried_accounts

        assert not missing_accounts, (
            f"Failed to find all user or group accounts with 'ALLOWS_COMPUTE_EXECUTE' risk within timeout period. "
            f"Missing accounts: {missing_accounts}"
        )

    def test_all_user_or_group_accounts_with_allows_storage_read_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        wait_for_gcp_identity_provider_ingestion,
        gcp_service_account
    ):
        """Verify that all deployed user or group accounts with 'ALLOWS_STORAGE_READ' risk are identified.

        Given:
            - A set of user or group accounts with roles related to 'ALLOWS_STORAGE_READ' risk,
            such as Storage Object Viewer, Storage Admin, Owner, deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The GCP organization name where these user or group accounts exist.

        When:
            - The test queries the Lacework API for user or group accounts flagged with 'ALLOWS_STORAGE_READ' risk
              within the time range.

        Then:
            - All deployed user or group accounts related to 'ALLOWS_STORAGE_READ' risk must be present in the API response.
            - The API response must correctly identify these user or group accounts as having the 'ALLOWS_STORAGE_READ' risk.

        Args:
            identity_v1_client: API client fixture for querying identities.
            wait_for_gcp_identity_provider_ingestion: Fixture ensuring identity updates post daily
                ingestion collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP service account details.
        """
        # User or group accounts with Storage read permissions
        gcp_iam_roles = GCP_RISKS_MAPPING["ALLOWS_STORAGE_READ"]
        role_names = []
        for role in gcp_iam_roles:
            role_names.extend(GCP_IAM_TO_ROLE.get(role, []))

        # Collect the emails of user or group accounts and match with principle id returned from lacework
        storage_read_accounts = []
        for role in role_names:
            if role in GCP_USER_ACCOUNT_EMAILS:
                # pre-defined user or group account
                storage_read_accounts.append(GCP_USER_ACCOUNT_EMAILS.get(role, "Unknown user account"))
            elif role in GCP_GROUP_ACCOUNT_EMAILS:
                # pre-defined group account
                storage_read_accounts.append(GCP_GROUP_ACCOUNT_EMAILS.get(role, "Unknown group account"))

        # Ensure at least one user or group account exists with a relevant role
        assert storage_read_accounts, "No user or group accounts with 'ALLOWS_STORAGE_READ' risk are deployed."

        logger.info(f"Expected user or group accounts with 'ALLOWS_STORAGE_READ' risk: {storage_read_accounts}")

        # Get ingestion start and end time from fixture
        time_range = wait_for_gcp_identity_provider_ingestion
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        # Get GCP organization name from the fixture
        org_name = gcp_service_account.org_name

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_STORAGE_READ", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_GOOGLE_ACCOUNT", "filterGroup": "include"}, {"value": "GCP_GOOGLE_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": org_name, "filterGroup": "include"}]
        }

        response = identity_v1_client.query_identities(
            start_time_range, end_time_range, filters)

        assert response.status_code == 200, f"Failed to query identities: {response.text}"

        # Parse API response
        response_data = response.json().get("data", [])
        queried_accounts = {account["PRINCIPAL_ID"] for account in response_data}

        # Validate all user or group accounts with storage read permissions appear in the API response
        missing_accounts = set(storage_read_accounts) - queried_accounts

        assert not missing_accounts, (
            f"Failed to find all user or group accounts with 'ALLOWS_STORAGE_READ' risk within timeout period. "
            f"Missing accounts: {missing_accounts}"
        )

    def test_all_user_or_group_accounts_with_allows_secrets_read_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        wait_for_gcp_identity_provider_ingestion,
        gcp_service_account
    ):
        """Verify that all deployed user or group accounts with 'ALLOWS_SECRETS_READ' risk are identified.

        Given:
            - A set of user or group accounts with roles related to 'ALLOWS_SECRETS_READ' risk,
            such as Secret Manager Admin, Owner, deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The GCP organization name where these user or group accounts exist.

        When:
            - The test queries the Lacework API for user or group accounts flagged with 'ALLOWS_SECRETS_READ' risk
              within the time range.

        Then:
            - All deployed user or group accounts with 'ALLOWS_SECRETS_READ' risk must be present in the API response.
            - The API response must correctly identify these user or group accounts as having the 'ALLOWS_SECRETS_READ' risk.

        Args:
            identity_v1_client: API client fixture for querying identities.
            wait_for_gcp_identity_provider_ingestion: Fixture ensuring identity updates post daily
                ingestion collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP service account details.
        """
        # User or group accounts with Secret read permissions
        gcp_iam_roles = GCP_RISKS_MAPPING["ALLOWS_SECRETS_READ"]
        role_names = []
        for role in gcp_iam_roles:
            role_names.extend(GCP_IAM_TO_ROLE.get(role, []))

        # Collect the emails of user or group accounts and match with principle id returned from lacework
        secrets_read_accounts = []
        for role in role_names:
            if role in GCP_USER_ACCOUNT_EMAILS:
                # pre-defined user or group account
                secrets_read_accounts.append(GCP_USER_ACCOUNT_EMAILS.get(role, "Unknown user account"))
            elif role in GCP_GROUP_ACCOUNT_EMAILS:
                # pre-defined group account
                secrets_read_accounts.append(GCP_GROUP_ACCOUNT_EMAILS.get(role, "Unknown group account"))

        # Ensure at least one user or group account exists with a relevant role
        assert secrets_read_accounts, "No user or group accounts with 'ALLOWS_SECRETS_READ' risk are deployed."

        logger.info(f"Expected user or group accounts with 'ALLOWS_SECRETS_READ' risk: {secrets_read_accounts}")

        # Get ingestion start and end time from fixture
        time_range = wait_for_gcp_identity_provider_ingestion
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        # Get GCP organization name from the fixture
        org_name = gcp_service_account.org_name

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_SECRETS_READ", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_GOOGLE_ACCOUNT", "filterGroup": "include"}, {"value": "GCP_GOOGLE_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": org_name, "filterGroup": "include"}]
        }

        response = identity_v1_client.query_identities(
            start_time_range, end_time_range, filters)

        assert response.status_code == 200, f"Failed to query identities: {response.text}"

        # Parse API response
        response_data = response.json().get("data", [])
        queried_accounts = {account["PRINCIPAL_ID"] for account in response_data}

        # Validate all user or group accounts with secrets read permissions appear in the API response
        missing_accounts = set(secrets_read_accounts) - queried_accounts

        assert not missing_accounts, (
            f"Failed to find all user or group accounts with 'ALLOWS_SECRETS_READ' risk within timeout period. "
            f"Missing accounts: {missing_accounts}"
        )

    def test_all_user_or_group_accounts_with_allows_full_admin_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        wait_for_gcp_identity_provider_ingestion,
        gcp_service_account
    ):
        """Verify that all deployed user or group accounts with 'ALLOWS_FULL_ADMIN' risk are identified.

        Given:
            - A set of user or group accounts with roles related to 'ALLOWS_FULL_ADMIN' risk,
              such as owner, deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The GCP organization name where these user or group accounts exist.

        When:
            - The test queries the Lacework API for user or group accounts flagged with 'ALLOWS_FULL_ADMIN' risk
              within the time range.

        Then:
            - All deployed user or group accounts with roles related to 'ALLOWS_FULL_ADMIN' risk must be present in the API response.
            - The API response must correctly identify these user or group accounts as having the 'ALLOWS_FULL_ADMIN' risk.

        Args:
            identity_v1_client: API client fixture for querying identities.
            wait_for_gcp_identity_provider_ingestion: Fixture ensuring identity updates post daily
                ingestion collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP service account details.
        """
        # User or group accounts with full admin roles
        gcp_iam_roles = GCP_RISKS_MAPPING["ALLOWS_FULL_ADMIN"]
        role_names = []
        for role in gcp_iam_roles:
            role_names.extend(GCP_IAM_TO_ROLE.get(role, []))

        # Collect the emails of user or group accounts and match with principle id returned from lacework
        full_admin_accounts = []
        for role in role_names:
            if role in GCP_USER_ACCOUNT_EMAILS:
                # pre-defined user or group account
                full_admin_accounts.append(GCP_USER_ACCOUNT_EMAILS.get(role, "Unknown user account"))
            elif role in GCP_GROUP_ACCOUNT_EMAILS:
                # pre-defined group account
                full_admin_accounts.append(GCP_GROUP_ACCOUNT_EMAILS.get(role, "Unknown group account"))

        # Ensure at least one user or group account exists with a relevant role
        assert full_admin_accounts, "No user or group accounts with 'ALLOWS_FULL_ADMIN' risk are deployed."

        logger.info(f"Expected user or group accounts with 'ALLOWS_FULL_ADMIN' risk: {full_admin_accounts}")

        # Get ingestion start and end time from fixture
        time_range = wait_for_gcp_identity_provider_ingestion
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        # Get GCP organization name from the fixture
        org_name = gcp_service_account.org_name

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_FULL_ADMIN", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_GOOGLE_ACCOUNT", "filterGroup": "include"}, {"value": "GCP_GOOGLE_GROUP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": org_name, "filterGroup": "include"}]
        }
        response = identity_v1_client.query_identities(
            start_time_range, end_time_range, filters)

        assert response.status_code == 200, f"Lacework API query failed: {response.json()}"
        # Parse API response
        response_data = response.json().get("data", [])
        queried_accounts = {account["PRINCIPAL_ID"] for account in response_data}

        # Validate all user or group accounts with full admin roles appear in the API response
        missing_accounts = set(full_admin_accounts) - queried_accounts

        assert not missing_accounts, (
            f"Failed to find all user or group accounts with 'ALLOWS_FULL_ADMIN' risk within timeout period. "
            f"Missing accounts: {missing_accounts}"
        )
