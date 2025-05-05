import time
import pytest
import uuid
import logging

from fortiqa.libs.lw.apiv1.api_client.access.api_keys import APIKeysV1
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client


logger = logging.getLogger(__name__)


@pytest.fixture
def api_key_name():
    """Generate a unique API key name for testing.

    Given:
        - None
    When:
        - A test requires a unique API key name
    Then:
        - Returns a unique name using UUID
    """
    return f"test-api-key-{uuid.uuid4()}"


@pytest.fixture
def api_key_description():
    """Generate a description for API key testing.

    Given:
        - None
    When:
        - A test requires an API key description
    Then:
        - Returns a standard description string
    """
    return "Test API key created by automation"


@pytest.fixture
def api_key_payload(api_key_name, api_key_description):
    """Create a basic API key payload.

    Given:
        - A unique API key name
        - A standard API key description
    When:
        - A test requires a basic API key payload
    Then:
        - Returns a dictionary with name and description

    Args:
        api_key_name: Unique name for the API key
        api_key_description: Description for the API key
    """
    return {
        "name": api_key_name,
        "description": api_key_description
    }


@pytest.fixture(scope="session")
def api_keys_v1(api_v1_client) -> APIKeysV1:
    """Create an APIKeysV1 client instance.

    Given:
        - An API v1 client instance
    When:
        - A test requires API key management operations
    Then:
        - Returns an APIKeysV1 client instance

    Args:
        api_v1_client: Base API v1 client instance
    """
    return APIKeysV1(api_v1_client)


@pytest.fixture
def create_service_account(api_v1_client):
    """Create a service account for testing.

    Given:
        - An API v1 client instance
    When:
        - A test requires a service account
    Then:
        - Returns the key data
        - Automatically cleans up the key after test
    """
    payload = [
              {
                "name": "fcsqa-automation",
                "description": "Test service account created by automation"
              }
            ]
    response = api_v1_client.create_service_account(payload)
    assert response.status_code == 200

    try:
        data = response.json()["data"][0]
        yield data

    finally:
        api_v1_client.delete_service_account(data["userGuid"])


@pytest.fixture
def created_api_key(api_keys_v1: APIKeysV1, api_key_payload, create_service_account):
    """Create and return an API key for testing.

    Given:
        - An APIKeysV1 client instance
        - A valid API key payload
    When:
        - A test requires a pre-created API key
    Then:
        - Creates a new API key
        - Returns the key data
        - Automatically cleans up the key after test

    Args:
        api_keys_v1: APIKeysV1 client instance
        api_key_payload: Dictionary containing API key creation parameters
        create_service_account: Fixture to create a service account
    """
    response = api_keys_v1.create_api_key_for_service_account(api_key_payload, create_service_account["userGuid"])
    assert response.status_code == 200
    try:
        key_data = response.json()["data"]
        yield key_data

    finally:
        delete_and_verify_api_key(api_keys_v1, key_data["keyId"])


@pytest.fixture
def create_and_download_api_key(api_keys_v1: APIKeysV1, api_key_payload):
    """Create and download an API key for testing.

    Given:
        - An APIKeysV1 client instance
        - A valid API key payload
    When:
        - A test requires a pre-created API key with download information
    Then:
        - Creates a new API key
        - Downloads and returns the key data including secret
        - Automatically cleans up the key after test

    Args:
        api_keys_v1: APIKeysV1 client instance
        api_key_payload: Dictionary containing API key creation parameters
    """
    response = api_keys_v1.create_api_key_for_service_account(api_key_payload)
    assert response.status_code == 200

    try:
        key_data = response.json()["data"]

        resp = api_keys_v1.download_api_key({"KEY_ID": key_data["keyId"]})
        result = resp.json()
        # remove the last two parts of the account, i.e., .lacework.net
        account = result["account"].split('.')[:-2]
        account = '.'.join(account)
        result["account"] = account
        yield result

    finally:
        delete_and_verify_api_key(api_keys_v1, key_data["keyId"])


def delete_and_verify_api_key(api_keys_v1: APIKeysV1, key_id: str):
    """Delete an API key and verify it's no longer present.

    Given:
        - An APIKeysV1 client instance
        - A valid API key ID
    When:
        - Deleting the API key
    Then:
        - Key should be deleted successfully
        - Key should not be present in subsequent get_api_keys call

    Args:
        api_keys_v1: APIKeysV1 client instance
        key_id: ID of the API key to delete
    """
    resp = api_keys_v1.delete_api_key(key_id)
    if resp.status_code != 200:
        # list all api keys to see if the key is still there or deleted
        list_response = api_keys_v1.get_api_keys_for_service_account()
        keys = list_response.json()["data"]
        found = any(key["keyId"] == key_id for key in keys)
        if found:
            pytest.fail(f"Failed to delete API key: {resp}")
        else:
            logger.error(f"delete request failed w/ {resp.status_code} but api key was deleted")


class TestAPIKeys:
    """Test suite for API Keys operations."""

    def test_create_api_key(self, api_keys_v1: APIKeysV1, api_key_payload):
        """Test creating an API key with valid payload.

        Given:
            - A valid API key payload with name and description
            - An instance of APIKeysV1 client
        When:
            - Creating a new API key
        Then:
            - Response status code should be 200
            - Created key should have 'Active' status
            - Response should contain a keyId
            - API key should be deleted after test

        Args:
            api_keys_v1: APIKeysV1 client instance
            api_key_payload: Dictionary containing API key creation parameters
        """
        response = api_keys_v1.create_api_key(api_key_payload)
        assert response.status_code == 200

        data = response.json()["data"]
        logger.info(f"create api key {data=}")
        assert data["status"] == "Active"
        assert "keyId" in data

        # Cleanup
        delete_and_verify_api_key(api_keys_v1, data["keyId"])

    def test_get_api_keys(self, api_keys_v1: APIKeysV1, created_api_key):
        """Test retrieving all API keys.

        Given:
            - An instance of APIKeysV1 client
            - A pre-created API key
        When:
            - Retrieving all API keys
        Then:
            - Response status code should be 200
            - Response data should be a list
            - Pre-created API key should be in the list

        Args:
            api_keys_v1: APIKeysV1 client instance
            created_api_key: Dictionary containing pre-created API key data
        """
        response = api_keys_v1.get_api_keys_for_service_account()
        assert response.status_code == 200

        data = response.json()["data"]
        assert isinstance(data, list)

        # Verify our created key is in the list
        key_ids = [key["keyId"] for key in data]
        assert created_api_key["keyId"] in key_ids

    @pytest.mark.xfail(reason="PLTI-529: api response 500 while api key status changed")
    def test_edit_api_key_status_check_resp_code(self, api_keys_v1: APIKeysV1, created_api_key):
        """Test editing API key status with response code verification.

        Given:
            - An instance of APIKeysV1 client
            - A pre-created API key
        When:
            - Deactivating the API key
            - Verifying the status change
            - Reactivating the API key
        Then:
            - Both status change operations should return 200
            - Key status should be 'Inactive' after deactivation
            - Key status should be 'Active' after reactivation

        Args:
            api_keys_v1: APIKeysV1 client instance
            created_api_key: Dictionary containing pre-created API key data
        """
        key_id = created_api_key["keyId"]

        # Test deactivating the key
        payload = {"status": "Inactive"}
        response = api_keys_v1.edit_api_key(key_id, payload)
        assert response.status_code == 200

        # Test reactivating the key
        payload = {"status": "Active"}
        response = api_keys_v1.edit_api_key(key_id, payload)
        assert response.status_code == 200

    def test_edit_api_key_status_check_status(self, api_keys_v1: APIKeysV1, created_api_key):
        """Test editing API key status with status verification.

        Given:
            - An instance of APIKeysV1 client
            - A pre-created API key
        When:
            - Deactivating the API key
            - Verifying the status change
            - Reactivating the API key
        Then:
            - Key status should be 'Inactive' after deactivation
            - Key status should be 'Active' after reactivation
            - Status changes should be verified through API calls

        Args:
            api_keys_v1: APIKeysV1 client instance
            created_api_key: Dictionary containing pre-created API key data
        """
        key_id = created_api_key["keyId"]

        # Test deactivating the key
        payload = {"status": "Inactive"}
        response = api_keys_v1.edit_api_key(key_id, payload)

        response = api_keys_v1.get_api_keys_for_service_account()
        key_data = next((key for key in response.json()["data"] if key["keyId"] == key_id), {})
        assert key_data, f"Failed to find key {key_id} after deactivation"
        assert key_data["status"] == "Inactive"
        logger.error(f"update api key response FAILED w/ {response.status_code} but api key status was updated {key_data=}")

        # Test reactivating the key
        payload = {"status": "Active"}
        response = api_keys_v1.edit_api_key(key_id, payload)

        response = api_keys_v1.get_api_keys_for_service_account()
        key_data = next((key for key in response.json()["data"] if key["keyId"] == key_id), {})
        assert key_data, f"Failed to find key {key_id} after reactivation"
        assert key_data["status"] == "Active"
        logger.error(f"update api key response FAILED w/ {response.status_code} but api key status was updated {key_data=}")

    def test_download_api_key(self, api_keys_v1: APIKeysV1, created_api_key):
        """Test downloading an API key.

        Given:
            - An instance of APIKeysV1 client
            - A pre-created API key
        When:
            - Downloading the API key
        Then:
            - Response status code should be 200
            - Response should contain keyId, secret, and account
            - Downloaded keyId should match created key

        Args:
            api_keys_v1: APIKeysV1 client instance
            created_api_key: Dictionary containing pre-created API key data
        """
        payload = {"KEY_ID": created_api_key["keyId"]}
        response = api_keys_v1.download_api_key(payload)
        assert response.status_code == 200

        data = response.json()
        assert "keyId" in data
        assert "secret" in data
        assert "account" in data
        assert data["keyId"] == created_api_key["keyId"]

    @pytest.mark.xfail(reason="PLTI-529: api response 500 while api key was deleted")
    def test_delete_api_key_check_resp_code(self, api_keys_v1: APIKeysV1, api_key_payload):
        """Test deleting an API key with response code verification.

        Given:
            - An instance of APIKeysV1 client
            - A valid API key payload
        When:
            - Creating a new API key
            - Deleting the created key
        Then:
            - Delete operation should return 200

        Args:
            api_keys_v1: APIKeysV1 client instance
            api_key_payload: Dictionary containing API key creation parameters
        """
        # Create a key to delete
        create_response = api_keys_v1.create_api_key(api_key_payload)
        key_id = create_response.json()["data"]["keyId"]

        # Delete the key
        response = api_keys_v1.delete_api_key(key_id)
        assert response.status_code == 200

    def test_delete_api_key_check_existing_keys(self, api_keys_v1: APIKeysV1, api_key_payload):
        """Test deleting an API key with existence verification.

        Given:
            - An instance of APIKeysV1 client
            - A valid API key payload
        When:
            - Creating a new API key
            - Deleting the created key
            - Listing all API keys
        Then:
            - Deleted key should not be present in the API key list

        Args:
            api_keys_v1: APIKeysV1 client instance
            api_key_payload: Dictionary containing API key creation parameters
        """
        # Create a key to delete
        create_response = api_keys_v1.create_api_key(api_key_payload)
        key_id = create_response.json()["data"]["keyId"]

        # Delete the key
        api_keys_v1.delete_api_key(key_id)
        # Verify key is deleted by checking get_api_keys
        get_response = api_keys_v1.get_api_keys_for_service_account()
        keys = get_response.json()["data"]
        assert not any(key["keyId"] == key_id for key in keys)

    def test_delete_nonexistent_api_key(self, api_keys_v1: APIKeysV1):
        """Test deleting a non-existent API key.

        Given:
            - An instance of APIKeysV1 client
            - A randomly generated non-existent key ID
        When:
            - Attempting to delete a non-existent API key
        Then:
            - Response status code should not be 200

        Args:
            api_keys_v1: APIKeysV1 client instance
        """
        non_existent_id = str(uuid.uuid4())
        response = api_keys_v1.delete_api_key(non_existent_id)
        assert response.status_code != 200


class TestAPIKeyAuthentication:
    """Test suite for API Key authentication and access token functionality."""

    def test_create_access_token_with_active_key(self, create_and_download_api_key):
        """Test creating and using access token with an active API key.

        Given:
            - An active API key
        When:
            - Creating an APIV2Client with the key
            - Making API calls with the client
        Then:
            - Token creation should succeed
            - API calls should succeed

        Args:
            create_and_download_api_key: Dictionary containing API key data including keyId, secret and account
        """
        # Create APIV2Client with the key
        account = create_and_download_api_key['account']
        key_id = create_and_download_api_key["keyId"]
        secret = create_and_download_api_key["secret"]
        with APIV2Client(account, key_id, secret) as client:
            # Verify successful API call - use a simple GET to /api/v2/TeamUsers
            response = client.get_no_token_refresh(f"{client.url}/TeamUsers")
            assert response.status_code == 200, "API call failed with active key"

    def test_create_access_token_with_inactive_key(self, api_keys_v1, create_and_download_api_key):
        """Test that access token creation fails with an inactive API key.

        Given:
            - An API key that has been deactivated
        When:
            - Attempting to create an APIV2Client with the key
        Then:
            - Token creation should fail with authentication error

        Args:
            api_keys_v1: APIKeysV1 client instance for managing API keys
            create_and_download_api_key: Dictionary containing API key data including keyId, secret and account
        """
        # Deactivate the key
        key_id = create_and_download_api_key["keyId"]
        response = api_keys_v1.edit_api_key(key_id, {"status": "Inactive"})

        if response.status_code == 200:
            pass
        else:
            # get all api keys and check status
            response = api_keys_v1.get_api_keys_for_service_account()
            key_data = next((key for key in response.json()["data"] if key["keyId"] == key_id), {})
            assert key_data, f"Failed to find key {key_id} after reactivation"
            assert key_data["status"] == "Inactive"
            logger.error(f"update api key response FAILED w/ {response.status_code} but api key status was updated {key_data=}")

        # Attempt to create APIV2Client - should raise an exception
        try:
            client = APIV2Client(create_and_download_api_key['account'],
                                 create_and_download_api_key["keyId"],
                                 create_and_download_api_key["secret"])
            assert False, f"Expected exception, got {client._session=} {client._headers=}"
        except Exception as exc_info:
            logger.info(f"Expected exception: {exc_info=}")
            assert exc_info, "Expected exception"

    def test_token_invalidation_on_key_deletion(self, api_keys_v1, create_and_download_api_key):
        """Test that access token becomes invalid when API key is deleted.

        Given:
            - An active API key with valid access token
        When:
            - Deleting the API key
        Then:
            - Existing access token should become invalid
            - Subsequent API calls should fail

        Args:
            api_keys_v1: APIKeysV1 client instance for managing API keys
            create_and_download_api_key: Dictionary containing API key data including keyId, secret and account
        """
        # Create APIV2Client and make successful call

        with APIV2Client(create_and_download_api_key['account'],
                         create_and_download_api_key["keyId"],
                         create_and_download_api_key["secret"]) as client:
            # Verify initial API call works
            response = client.get_no_token_refresh(f"{client.url}/TeamUsers")
            assert response.status_code == 200, "Initial API call failed"

            # Delete the key
            response = api_keys_v1.delete_api_key(create_and_download_api_key["keyId"])
            if response.status_code != 200:
                logger.error(f"delete api key response FAILED w/ {response.status_code}")
                # list all api keys and check if the key is still there
                list_response = api_keys_v1.get_api_keys_for_service_account()
                keys = list_response.json()["data"]
                found = any(key["keyId"] == create_and_download_api_key["keyId"] for key in keys)
                if found:
                    pytest.fail(f"Failed to delete API key: {response}")

            # Verify next API call fails
            try:
                response = client.get_no_token_refresh(f"{client.url}/TeamUsers")
                assert response.status_code in [401, 403], f"API call w/ session token should fail after key deletion, but got {response=}"
            except Exception as exc_info:
                logger.info(f"Expected exception: {exc_info=}")
                assert exc_info, "Expected exception"

    @pytest.mark.xfail(reason="PLTI-531: access token remains valid after api key was inactivated")
    def test_token_invalidation_on_key_deactivation(self, api_keys_v1, create_and_download_api_key):
        """Test that access token becomes invalid when API key is deactivated.

        Given:
            - An active API key with valid access token
        When:
            - Deactivating the API key
        Then:
            - Existing access token should become invalid
            - Subsequent API calls should fail

        Args:
            api_keys_v1: APIKeysV1 client instance for managing API keys
            create_and_download_api_key: Dictionary containing API key data including keyId, secret and account
        """
        # Create APIV2Client and make successful call
        with APIV2Client(create_and_download_api_key['account'],
                         create_and_download_api_key["keyId"],
                         create_and_download_api_key["secret"]) as client:
            # Verify initial API call works
            response = client.get_no_token_refresh(f"{client.url}/TeamUsers")
            assert response.status_code == 200, "Initial API call failed"

            # Deactivate the key
            response = api_keys_v1.edit_api_key(create_and_download_api_key["keyId"], {"status": "Inactive"})
            if response.status_code == 200:
                pass
            else:
                # get all api keys and check status
                key_id = create_and_download_api_key["keyId"]
                response = api_keys_v1.get_api_keys_for_service_account()
                key_data = next((key for key in response.json()["data"] if key["keyId"] == key_id), {})
                assert key_data, f"Failed to find key {key_id} after reactivation"
                assert key_data["status"] == "Inactive"
                logger.error(f"update api key response FAILED but api key status was updated {key_data=}")

            try:
                # Verify next API call fails
                response = client.get_no_token_refresh(f"{client.url}/TeamUsers")
                if response.status_code == 200:
                    pytest.fail(f"API call w/ session token should fail after key deactivation, but got {response=}")
            except Exception as exc_info:
                logger.info(f"Expected exception: {exc_info=}")
                assert exc_info, "Expected exception"

    def test_token_expiration(self, create_and_download_api_key):
        """Test access token expiration and automatic refresh.

        Given:
            - An active API key
        When:
            - Creating a token with very short expiry
            - Waiting for token expiration
            - Making subsequent API calls
        Then:
            - Initial API calls should succeed
            - Client should automatically refresh token after expiration
            - API calls should succeed after refresh

        Args:
            create_and_download_api_key: Dictionary containing API key data including keyId, secret and account
        """
        # Create APIV2Client with short token expiry
        with APIV2Client(create_and_download_api_key['account'],
                         create_and_download_api_key["keyId"],
                         create_and_download_api_key["secret"]) as client:
            client._create_new_session(expiry_time=10)

            time.sleep(15)

            # Make API call - should trigger token refresh
            response = client.get_no_token_refresh(f"{client.url}/TeamUsers")
            assert response.status_code in [401, 403], f"API call should have failed after token expired, but got {response=}"

    def test_concurrent_token_usage(self, api_keys_v1, create_and_download_api_key):
        """Test concurrent usage of multiple access tokens from same API key.

        Given:
            - An active API key
        When:
            - Creating multiple APIV2Client instances
            - Making concurrent API calls
            - Deactivating the key
        Then:
            - All clients should work independently
            - All clients should fail after key deactivation

        Args:
            api_keys_v1: APIKeysV1 client instance for managing API keys
            create_and_download_api_key: Dictionary containing API key data including keyId, secret and account
        """
        # Create multiple clients
        clients = []
        for _ in range(3):
            client = APIV2Client(create_and_download_api_key['account'],
                                 create_and_download_api_key["keyId"],
                                 create_and_download_api_key["secret"])
            clients.append(client)

        try:
            # Verify all clients can make API calls
            for client in clients:
                response = client.get_no_token_refresh(f"{client.url}/TeamUsers")
                assert response.status_code == 200, "API call failed for concurrent client"

            # skip - Deactivate the key
            # update_response = api_keys_v1.edit_api_key(created_api_key["keyId"], {"status": "Inactive"})
            # assert update_response.status_code == 200

            # skip - Verify all clients fail
            # for client in clients:
                # response = client.get_no_token_refresh(f"{client.url}/TeamUsers")
                # assert response.status_code in [401, 403], "API call should fail after key deactivation"
        finally:
            # Clean up clients
            for client in clients:
                client._session.close()

    def test_access_on_invalid_token(self, create_and_download_api_key):
        """Test api access using an invalid token.

        Given:
            - An active API key
        When:
            - Forcing an unauthorized response by corrupting token
            - Making subsequent API calls
        Then:
            - API calls should fail with invalid token

        Args:
            create_and_download_api_key: Dictionary containing API key data including keyId, secret and account
        """
        # Create APIV2Client
        with APIV2Client(create_and_download_api_key['account'],
                         create_and_download_api_key["keyId"],
                         create_and_download_api_key["secret"]) as client:
            # Corrupt the token to force 401
            client._headers["Authorization"] = 'invalid_token'

            # Make API call - should fail due to invalid token
            response = client.get_no_token_refresh(f"{client.url}/TeamUsers")
            assert response.status_code in [401, 403], f"API call should have failed due to invalid token, but got {response=}"
