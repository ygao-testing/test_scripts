import logging
import pytest
from fortiqa.libs.lw.apiv1.api_client.identity.identity import IdentityV1
from fortiqa.tests.e2e.ingestion.gcp.identity.risk_mappings import GCP_RISKS_MAPPING, GCP_IAM_TO_ROLE
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


class TestIdentityGCPServiceAccountV1:
    def test_all_deployed_gcp_service_accounts_exist_in_lacework(
        self,
        e2e_gcp_resources,
        wait_for_identity_update_post_daily_ingestion_gcp,
        identity_v1_client,
        gcp_service_account
    ):
        """
        Verify that all GCP service accounts deployed exist in Lacework.

        Given:
            - A list of service accounts deployed in GCP.
            - The Lacework API which provides service account identity data.
            - A time range corresponding to the daily collection start and end time.

        When:
            - Querying Lacework for service accounts filtered by GCP project within the given collection time range.

        Then:
            - Validate that all service accounts from GCP exist in Lacework's response.

        Args:
            e2e_gcp_resources: Fixture providing access to Terraform resources.
            identity_v1_client: Instance of IdentityV1 for making API calls.
            wait_for_identity_update_post_daily_ingestion_gcp: Fixture ensuring identity updates post daily ingestion
            collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP project details.
        """
        # Extract GCP service accounts from Terraform output
        service_account_identity_module = e2e_gcp_resources["service_account_identity"]["tf"]
        service_account_names = service_account_identity_module.output().get("service_account_names", {})

        logger.info(f"Deployed GCP service accounts: {service_account_names}")

        # Ensure we have service accounts to test
        assert service_account_names, "No service accounts found in GCP project."

        # Extract service account details
        gcp_service_account_display_names = dict(service_account_names.items())

        logger.info(f"Deployed GCP service accounts: {gcp_service_account_display_names}")

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_update_post_daily_ingestion_gcp
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        project_id = gcp_service_account.project_id

        # Construct Lacework API filters for GCP service accounts
        lacework_filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_SERVICE_ACCOUNT", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": project_id, "filterGroup": "include"}]
        }

        # Query Lacework API
        logger.info(f"Querying Lacework for GCP service accounts in project {project_id}")
        lacework_response = identity_v1_client.query_identities(
            start_time_range=start_time_range,
            end_time_range=end_time_range,
            filters=lacework_filters
        )

        # Ensure API response status is 200
        assert lacework_response.status_code == 200, f"Lacework API query failed: {lacework_response.json()}"
        logger.info(f"Lacework API query successful. Response: {lacework_response.json()}")

        # Extract emails from Lacework response data (which is the unique identifier for service accounts)
        lacework_service_account_names = {account["NAME"] for account in lacework_response.json().get("data", [])}

        # Extract GCP service account emails from Terraform output
        gcp_service_account_names = list(gcp_service_account_display_names.values())

        logger.info(f"Expected GCP service account emails: {gcp_service_account_names}")

        # Compare service account emails from GCP with Lacework
        missing_accounts = set(gcp_service_account_names) - lacework_service_account_names

        # If we reach here, we've timed out
        assert not missing_accounts, (
            f"Failed to find all service accounts within timeout period. "
            f"Missing accounts: {missing_accounts}"
        )

    def test_all_service_accounts_with_allows_iam_write_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_gcp_resources,
        wait_for_identity_properties_update_post_daily_ingestion_gcp,
        gcp_service_account
    ):
        """Verify that all deployed service accounts with 'ALLOWS_IAM_WRITE' risk are identified.

        Given:
            - A set of service accounts with roles related to 'ALLOWS_IAM_WRITE' risk,
            such as owner, storage.admin, cloudfunctions.admin, secretmanager.admin, and compute.admin, deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The GCP project ID where these service accounts exist.

        When:
            - The test queries the Lacework API for service accounts flagged with 'ALLOWS_IAM_WRITE' risk
              within the time range.

        Then:
            - All deployed service accounts with roles related to 'ALLOWS_IAM_WRITE' risk must be present in the API response.
            - The API response must correctly identify these service accounts as having the 'ALLOWS_IAM_WRITE' risk.

        Args:
            identity_v1_client: API client fixture for querying identities.
            e2e_gcp_resources: Fixture providing Terraform deployment details.
            wait_for_identity_properties_update_post_daily_ingestion_gcp: Fixture ensuring identity properties updates post daily
                ingestion collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP service account details.
        """
        # Extract IAM roles by policy from Terraform output
        service_account_identity_module = e2e_gcp_resources["service_account_identity"]["tf"]
        service_account_names = service_account_identity_module.output().get("service_account_names", {})

        # Extract role assignments from domain.tf analysis (roles defined in our Terraform)
        # Service accounts with IAM admin role
        gcp_iam_roles = GCP_RISKS_MAPPING["ALLOWS_IAM_WRITE"]
        role_names = [GCP_IAM_TO_ROLE[role] for role in gcp_iam_roles]
        iam_admin_accounts = [service_account_names.get(role) for role in role_names]

        # Ensure at least one service account exists with a relevant role
        assert iam_admin_accounts, "No service accounts with 'ALLOWS_IAM_WRITE' risk are deployed."

        logger.info(f"Expected service accounts with 'ALLOWS_IAM_WRITE' risk: {iam_admin_accounts}")

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_properties_update_post_daily_ingestion_gcp
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        # Get GCP project ID from the fixture
        project_id = gcp_service_account.project_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_IAM_WRITE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_SERVICE_ACCOUNT", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": project_id, "filterGroup": "include"}]
        }
        response = identity_v1_client.query_identities(
            start_time_range, end_time_range, filters)

        assert response.status_code == 200, f"Lacework API query failed: {response.json()}"
        # Parse API response
        response_data = response.json().get("data", [])
        queried_accounts = {account["NAME"] for account in response_data}

        # Validate all service accounts with IAM admin roles appear in the API response
        missing_accounts = set(iam_admin_accounts) - queried_accounts

        assert not missing_accounts, (
            f"Failed to find all service accounts with 'ALLOWS_IAM_WRITE' risk within timeout period. "
            f"Missing accounts: {missing_accounts}"
        )

    def test_all_service_accounts_with_allows_storage_write_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_gcp_resources,
        wait_for_identity_properties_update_post_daily_ingestion_gcp,
        gcp_service_account
    ):
        """Verify that all deployed service accounts with 'ALLOWS_STORAGE_WRITE' risk are identified.

        Given:
            - A set of service accounts with roles related to 'ALLOWS_STORAGE_WRITE' risk,
            such as Storage Admin, Owner, deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The GCP project ID where these service accounts exist.

        When:
            - The test queries the Lacework API for service accounts flagged with 'ALLOWS_STORAGE_WRITE' risk
              within the time range.

        Then:
            - All deployed service accounts related to 'ALLOWS_STORAGE_WRITE' risk must be present in the API response.
            - The API response must correctly identify these service accounts as having the 'ALLOWS_STORAGE_WRITE' risk.

        Args:
            identity_v1_client: API client fixture for querying identities.
            e2e_gcp_resources: Fixture providing Terraform deployment details.
            wait_for_identity_properties_update_post_daily_ingestion_gcp: Fixture ensuring identity properties updates post daily
                ingestion collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP service account details.
        """
        # Extract IAM roles by policy from Terraform output
        service_account_identity_module = e2e_gcp_resources["service_account_identity"]["tf"]
        service_account_names = service_account_identity_module.output().get("service_account_names", {})

        # Extract role assignments from domain.tf analysis (roles defined in our Terraform)
        # Service accounts with Storage Admin role
        gcp_iam_roles = GCP_RISKS_MAPPING["ALLOWS_STORAGE_WRITE"]
        role_names = [GCP_IAM_TO_ROLE[role] for role in gcp_iam_roles]
        storage_admin_accounts = [service_account_names.get(role) for role in role_names]

        # Ensure at least one service account exists with a relevant role
        assert storage_admin_accounts, "No service accounts with 'ALLOWS_STORAGE_WRITE' risk are deployed."

        logger.info(f"Expected service accounts with 'ALLOWS_STORAGE_WRITE' risk: {storage_admin_accounts}")

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_properties_update_post_daily_ingestion_gcp
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]
        # Get GCP project ID from the fixture
        project_id = gcp_service_account.project_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_STORAGE_WRITE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_SERVICE_ACCOUNT", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": project_id, "filterGroup": "include"}]
        }

        response = identity_v1_client.query_identities(
            start_time_range, end_time_range, filters)

        assert response.status_code == 200, f"Failed to query identities: {response.text}"

        # Parse API response
        response_data = response.json().get("data", [])
        queried_accounts = {account["NAME"] for account in response_data}

        # Validate all service accounts with Storage Admin roles appear in the API response
        missing_accounts = set(storage_admin_accounts) - queried_accounts

        assert not missing_accounts, (
            f"Failed to find all service accounts with 'ALLOWS_STORAGE_WRITE' risk within timeout period. "
            f"Missing accounts: {missing_accounts}"
        )

    def test_all_service_accounts_with_allows_compute_execute_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_gcp_resources,
        wait_for_identity_properties_update_post_daily_ingestion_gcp,
        gcp_service_account
    ):
        """Verify that all deployed service accounts with 'ALLOWS_COMPUTE_EXECUTE' risk are identified.

        Given:
            - A set of service accounts with roles related to 'ALLOWS_COMPUTE_EXECUTE' risk,
            such as Compute Admin, Cloud Functions Admin, Owner, deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The GCP project ID where these service accounts exist.

        When:
            - The test queries the Lacework API for service accounts flagged with 'ALLOWS_COMPUTE_EXECUTE' risk within the time range.

        Then:
            - All deployed service accounts with 'ALLOWS_COMPUTE_EXECUTE' risk must be present in the API response.
            - The API response must correctly identify these service accounts as having the 'ALLOWS_COMPUTE_EXECUTE' risk.

        Args:
            identity_v1_client: API client fixture for querying identities.
            e2e_gcp_resources: Fixture providing Terraform deployment details.
            wait_for_identity_properties_update_post_daily_ingestion_gcp: Fixture ensuring identity properties updates post daily
                ingestion collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP service account details.
        """
        # Extract IAM roles by policy from Terraform output
        service_account_identity_module = e2e_gcp_resources["service_account_identity"]["tf"]
        service_account_names = service_account_identity_module.output().get("service_account_names", {})

        # Extract role assignments from domain.tf analysis (roles defined in our Terraform)
        # Service accounts with Compute execution permissions
        gcp_iam_roles = GCP_RISKS_MAPPING["ALLOWS_COMPUTE_EXECUTE"]
        role_names = [GCP_IAM_TO_ROLE[role] for role in gcp_iam_roles]
        compute_execute_accounts = [service_account_names.get(role) for role in role_names]

        # Ensure at least one service account exists with a relevant role
        assert compute_execute_accounts, "No service accounts with 'ALLOWS_COMPUTE_EXECUTE' risk are deployed."

        logger.info(f"Expected service accounts with 'ALLOWS_COMPUTE_EXECUTE' risk: {compute_execute_accounts}")

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_properties_update_post_daily_ingestion_gcp
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        # Get GCP project ID from the fixture
        project_id = gcp_service_account.project_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_COMPUTE_EXECUTE", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_SERVICE_ACCOUNT", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": project_id, "filterGroup": "include"}]
        }

        response = identity_v1_client.query_identities(
            start_time_range, end_time_range, filters)

        assert response.status_code == 200, f"Failed to query identities: {response.text}"
        # Parse API response
        response_data = response.json().get("data", [])
        queried_accounts = {account["NAME"] for account in response_data}

        # Validate all service accounts with compute execution permissions appear in the API response
        missing_accounts = set(compute_execute_accounts) - queried_accounts

        assert not missing_accounts, (
            f"Failed to find all service accounts with 'ALLOWS_COMPUTE_EXECUTE' risk within timeout period. "
            f"Missing accounts: {missing_accounts}"
        )

    def test_all_service_accounts_with_allows_storage_read_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_gcp_resources,
        wait_for_identity_properties_update_post_daily_ingestion_gcp,
        gcp_service_account
    ):
        """Verify that all deployed service accounts with 'ALLOWS_STORAGE_READ' risk are identified.

        Given:
            - A set of service accounts with roles related to 'ALLOWS_STORAGE_READ' risk,
            such as Storage Object Viewer, Storage Admin, Owner, deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The GCP project ID where these service accounts exist.

        When:
            - The test queries the Lacework API for service accounts flagged with 'ALLOWS_STORAGE_READ' risk
              within the time range.

        Then:
            - All deployed service accounts related to 'ALLOWS_STORAGE_READ' risk must be present in the API response.
            - The API response must correctly identify these service accounts as having the 'ALLOWS_STORAGE_READ' risk.

        Args:
            identity_v1_client: API client fixture for querying identities.
            e2e_gcp_resources: Fixture providing Terraform deployment details.
            wait_for_identity_properties_update_post_daily_ingestion_gcp: Fixture ensuring identity properties updates post daily
                ingestion collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP service account details.
        """
        # Extract IAM roles by policy from Terraform output
        service_account_identity_module = e2e_gcp_resources["service_account_identity"]["tf"]
        service_account_names = service_account_identity_module.output().get("service_account_names", {})

        # Extract role assignments from domain.tf analysis (roles defined in our Terraform)
        # Service accounts with Storage read permissions
        gcp_iam_roles = GCP_RISKS_MAPPING["ALLOWS_STORAGE_READ"]
        role_names = [GCP_IAM_TO_ROLE[role] for role in gcp_iam_roles]
        storage_read_accounts = [service_account_names.get(role) for role in role_names]

        # Ensure at least one service account exists with a relevant role
        assert storage_read_accounts, "No service accounts with 'ALLOWS_STORAGE_READ' risk are deployed."

        logger.info(f"Expected service accounts with 'ALLOWS_STORAGE_READ' risk: {storage_read_accounts}")

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_properties_update_post_daily_ingestion_gcp
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        # Get GCP project ID from the fixture
        project_id = gcp_service_account.project_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_STORAGE_READ", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_SERVICE_ACCOUNT", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": project_id, "filterGroup": "include"}]
        }

        response = identity_v1_client.query_identities(
            start_time_range, end_time_range, filters)

        assert response.status_code == 200, f"Failed to query identities: {response.text}"

        # Parse API response
        response_data = response.json().get("data", [])
        queried_accounts = {account["NAME"] for account in response_data}

        # Validate all service accounts with storage read permissions appear in the API response
        missing_accounts = set(storage_read_accounts) - queried_accounts

        assert not missing_accounts, (
            f"Failed to find all service accounts with 'ALLOWS_STORAGE_READ' risk within timeout period. "
            f"Missing accounts: {missing_accounts}"
        )

    def test_all_service_accounts_with_allows_secrets_read_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_gcp_resources,
        wait_for_identity_properties_update_post_daily_ingestion_gcp,
        gcp_service_account
    ):
        """Verify that all deployed service accounts with 'ALLOWS_SECRETS_READ' risk are identified.

        Given:
            - A set of service accounts with roles related to 'ALLOWS_SECRETS_READ' risk,
            such as Secret Manager Admin, Owner, deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The GCP project ID where these service accounts exist.

        When:
            - The test queries the Lacework API for service accounts flagged with 'ALLOWS_SECRETS_READ' risk
              within the time range.

        Then:
            - All deployed service accounts with Secret read permissions must be present in the API response.
            - The API response must correctly identify these service accounts as having the 'ALLOWS_SECRETS_READ' risk.

        Args:
            identity_v1_client: API client fixture for querying identities.
            e2e_gcp_resources: Fixture providing Terraform deployment details.
            wait_for_identity_properties_update_post_daily_ingestion_gcp: Fixture ensuring identity properties updates post daily
                ingestion collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP service account details.
        """
        # Extract IAM roles by policy from Terraform output
        service_account_identity_module = e2e_gcp_resources["service_account_identity"]["tf"]
        service_account_names = service_account_identity_module.output().get("service_account_names", {})

        # Extract role assignments from domain.tf analysis (roles defined in our Terraform)
        # Service accounts with Secret read permissions
        gcp_iam_roles = GCP_RISKS_MAPPING["ALLOWS_SECRETS_READ"]
        role_names = [GCP_IAM_TO_ROLE[role] for role in gcp_iam_roles]
        secrets_read_accounts = [service_account_names.get(role) for role in role_names]

        # Ensure at least one service account exists with a relevant role
        assert secrets_read_accounts, "No service accounts with 'ALLOWS_SECRETS_READ' risk are deployed."

        logger.info(f"Expected service accounts with 'ALLOWS_SECRETS_READ' risk: {secrets_read_accounts}")

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_properties_update_post_daily_ingestion_gcp
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        # Get GCP project ID from the fixture
        project_id = gcp_service_account.project_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_SECRETS_READ", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_SERVICE_ACCOUNT", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": project_id, "filterGroup": "include"}]
        }

        response = identity_v1_client.query_identities(
            start_time_range, end_time_range, filters)

        assert response.status_code == 200, f"Failed to query identities: {response.text}"

        # Parse API response
        response_data = response.json().get("data", [])
        queried_accounts = {account["NAME"] for account in response_data}

        # Validate all service accounts with secrets read permissions appear in the API response
        missing_accounts = set(secrets_read_accounts) - queried_accounts

        assert not missing_accounts, (
            f"Failed to find all service accounts with 'ALLOWS_SECRETS_READ' risk within timeout period. "
            f"Missing accounts: {missing_accounts}"
        )

    def test_all_service_accounts_with_allows_full_admin_risk_found_in_lacework_identity(
        self,
        identity_v1_client,
        e2e_gcp_resources,
        wait_for_identity_properties_update_post_daily_ingestion_gcp,
        gcp_service_account
    ):
        """Verify that all deployed service accounts with 'ALLOWS_FULL_ADMIN' risk are identified.

        Given:
            - A set of service accounts with roles related to 'ALLOWS_FULL_ADMIN' risk,
              such as owner, deployed via Terraform.
            - The identity properties update time range post daily collection completion.
            - The GCP project ID where these service accounts exist.

        When:
            - The test queries the Lacework API for service accounts flagged with 'ALLOWS_FULL_ADMIN' risk
              within the time range.

        Then:
            - All deployed service accounts with roles related to 'ALLOWS_FULL_ADMIN' risk must be present in the API response.
            - The API response must correctly identify these service accounts as having the 'ALLOWS_FULL_ADMIN' risk.

        Args:
            identity_v1_client: API client fixture for querying identities.
            e2e_gcp_resources: Fixture providing Terraform deployment details.
            wait_for_identity_properties_update_post_daily_ingestion_gcp: Fixture ensuring identity properties updates post daily
                ingestion collection completion and providing a valid time filter.
            gcp_service_account: Fixture providing GCP service account details.
        """
        # Extract IAM roles by policy from Terraform output
        service_account_identity_module = e2e_gcp_resources["service_account_identity"]["tf"]
        service_account_names = service_account_identity_module.output().get("service_account_names", {})

        # Extract role assignments from domain.tf analysis (roles defined in our Terraform)
        # Service accounts with full admin roles
        gcp_iam_roles = GCP_RISKS_MAPPING["ALLOWS_FULL_ADMIN"]
        role_names = [GCP_IAM_TO_ROLE[role] for role in gcp_iam_roles]
        full_admin_accounts = [service_account_names.get(role) for role in role_names]

        # Ensure at least one service account exists with a relevant role
        assert full_admin_accounts, "No service accounts with 'ALLOWS_FULL_ADMIN' risk are deployed."

        logger.info(f"Expected service accounts with 'ALLOWS_FULL_ADMIN' risk: {full_admin_accounts}")

        # Get ingestion start and end time from fixture
        time_range = wait_for_identity_properties_update_post_daily_ingestion_gcp
        start_time_range = time_range["start_time_range"]
        end_time_range = time_range["end_time_range"]

        # Get GCP project ID from the fixture
        project_id = gcp_service_account.project_id

        # Define API query filters
        filters = {
            "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
                {"value": "ALLOWS_FULL_ADMIN", "filterGroup": "include"}
            ],
            "CIEM_Identities_Filter.PROVIDER": [{"value": "GCP", "filterGroup": "include"}],
            "CIEM_Identities_Filter.IDENTITY_TYPE": [{"value": "GCP_SERVICE_ACCOUNT", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": project_id, "filterGroup": "include"}]
        }
        response = identity_v1_client.query_identities(
            start_time_range, end_time_range, filters)

        assert response.status_code == 200, f"Lacework API query failed: {response.json()}"
        # Parse API response
        response_data = response.json().get("data", [])
        queried_accounts = {account["NAME"] for account in response_data}

        # Validate all service accounts with full admin roles appear in the API response
        missing_accounts = set(full_admin_accounts) - queried_accounts

        assert not missing_accounts, (
            f"Failed to find all service accounts with 'ALLOWS_FULL_ADMIN' risk within timeout period. "
            f"Missing accounts: {missing_accounts}"
        )
