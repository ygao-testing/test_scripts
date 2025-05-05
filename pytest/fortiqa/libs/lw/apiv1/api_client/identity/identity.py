import logging
import requests
import time
from datetime import datetime, timezone
from fortiqa.libs.helper.date_helper import datetime_to_timestamp
logger = logging.getLogger(__name__)


class IdentityV1:

    def __init__(self, api_v1_client) -> None:
        self._user_api = api_v1_client
        self._base_url = f"{api_v1_client.url}/card/query"
        # Define all endpoints
        self._endpoints = {
            "identities": f"{self._base_url}/CIEM_Identities_RecalculatingInventoryTable",
            "identity_summary": f"{self._base_url}/CIEM_IdentityDetails_RecalculatingIdentitySummaryByIdentityUrn",
            "identity_entitlements_for_resource_type": f"{self._base_url}/CIEM_IdentityDetails_EntitlementsForResourceTypeByIdentity",
            "identity_entitlements_summary": f"{self._base_url}/CIEM_IdentityDetails_EntitlementsSummaryByIdentityUrn"

        }

    def query_identities(self, start_time_range: int, end_time_range: int, filters: dict | None = None) -> requests.Response:
        """
        Query CIEM identities with dynamically built filters.

        :param start_time_range: Start timestamp in milliseconds
        :param end_time_range: End timestamp in milliseconds
        :param filters: Optional dictionary of filters with include/exclude groupsF
        :return: requests.Response object
        """
        payload = {
            "ParamInfo": {
                "StartTimeRange": start_time_range,
                "EndTimeRange": end_time_range
            },
            "Filters": filters if filters else {}  # Use provided filters or empty dict
        }
        logger.info(f"Making request to API: {self._endpoints['identities']}")
        logger.info(f"Querying identities with payload: {payload}")
        # Make the API request and return the Response object
        return self._user_api.post(url=self._endpoints["identities"], payload=payload)

    def get_identity_summary_by_urn(self, identity_urn: str, start_time: int) -> requests.Response:
        """Retrieve the identity summary for a given identity URN within a specified start time.

        Given:
            - A unique identity URN.
            - A start timestamp in milliseconds.

        When:
            - Querying the API for detailed identity summary using 'CIEM_IdentityDetails_RecalculatingIdentitySummaryByIdentityUrn'.

        Then:
            - The API should return a response containing the identity summary.

        Args:
            identity_urn (str): The unique identifier for an identity.
            start_time (int): The start timestamp in milliseconds.

        Returns:
            requests.Response: The API response object.
        """
        url = self._endpoints["identity_summary"]  # Fetching URL for the specific endpoint
        payload = {
            "ParamInfo": {
                "IdentityUrn": identity_urn,
                "StartTime": start_time
            }
        }
        logger.info(f"Making request to API: {url}")
        logger.info(f"Payload: {payload}")

        return self._user_api.post(url=url, payload=payload)

    def get_identity_entitlements_summary_by_urn(
        self, identity_urn: str, start_time: int, excessive_unused_days: int = 0
    ) -> requests.Response:
        """
        Retrieve the entitlements summary for a specific identity using its URN.

        Given:
            - An Identity URN.
            - A start time in milliseconds.
            - (Optional) Excessive unused days (default: 0).

        When:
            - Querying the API for the entitlements summary.

        Then:
            - The API returns the summary of entitlements associated with the identity.

        Args:
            identity_urn (str): The URN of the identity.
            start_time (int): The start time in milliseconds for the query.
            excessive_unused_days (int, optional): Number of days for excessive unused entitlements (default: 0).

        Returns:
            requests.Response: The API response containing entitlements summary.
        """
        url = self._endpoints["identity_entitlements_summary"]
        payload = {
            "ParamInfo": {
                "IdentityUrn": identity_urn,
                "StartTime": start_time,
                "ExcessiveUnusedDays": excessive_unused_days,
            }
        }

        logger.info(f"Making request to API: {url}")
        logger.info(
            f"Querying identity entitlements summary with payload: {payload}")

        return self._user_api.post(url=url, payload=payload)

    def get_identity_entitlements_for_resource_type(
        self, resource_type: str, identity_urn: str, start_time: int, excessive_unused_days: int = 0
    ) -> requests.Response:
        """
        Fetch identity entitlements for a specific resource type.

        Args:
            resource_type (str): The type of resource (e.g., "ecs").
            identity_urn (str): Identity URN.
            start_time (int): Start timestamp in milliseconds.
            excessive_unused_days (int, optional): Days of unused entitlement threshold. Defaults to 0.

        Returns:
            requests.Response: API response object.
        """
        payload = {
            "ParamInfo": {
                "ResourceType": resource_type,
                "IdentityUrn": identity_urn,
                "StartTime": start_time,
                "ExcessiveUnusedDays": excessive_unused_days
            }
        }
        logger.info(
            f"Making request to API: {self._endpoints['identity_entitlements_for_resource_type']}")
        logger.info(
            f"Querying identity entitlements for resource type '{resource_type}' with payload: {payload}")

        return self._user_api.post(url=self._endpoints["identity_entitlements_for_resource_type"], payload=payload)

    def get_all_identity_by_cloud_provider(self, start_time_range: int, end_time_range: int, cloud_provider: str) -> requests.Response:
        """
        Query all identities by cloud provider.

        Args:
            start_time_range (int): Start timestamp in milliseconds.
            end_time_range (int): End timestamp in milliseconds.
            cloud_provider (str): Cloud provider name used for filtering.

        Returns:
            requests.Response: The API response object.
        """
        filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": cloud_provider, "filterGroup": "include"}]
        }

        return self.query_identities(start_time_range, end_time_range, filters)

    def check_for_identity_update(self, start_time_range: int, end_time_range: int, owner: str, cloud_provider: str, account_id: str = "", timeout_seconds: int = 60) -> bool:
        """Wait for the identity update to complete within the specified timeout.

        This method continuously queries the API for identity updates within the given time range.
        It verifies whether at least one record exists where the 'NAME' field starts with the specified 'owner'.
        This ensures that the identity update has completed successfully, as at least one of the resources
        deployed before ingestion should appear in the response after ingestion completion.

        The 'end_time_range' is dynamically updated to the current UTC time at each iteration, ensuring that
        the search window extends to include any newly updated identity records.

        Args:
            start_time_range (int): Start timestamp in milliseconds.
            end_time_range (int): End timestamp in milliseconds.
            owner (str): The prefix used to identify resources that should be present post-update.
            cloud_provider (str): Cloud provider name used for filtering.
            account_id (str): AWS account ID used for filtering (default: ""). If empty, no filtering by account ID is applied.
            timeout_seconds (int): Maximum time (in seconds) to wait for the update.

        Returns:
            bool: True if the identity update completes within the timeout, False otherwise.

        Note:
            - In the API response for identity records, each record contains a 'NAME' field.
            - When querying between the daily collection start time and the current time after actual daily collection completion,
              if the identity update is completed, at least one record should have a 'NAME' starting with 'owner'.
            - The 'end_time_range' is updated to the current time in each iteration to ensure that
              the search range includes any new updates occurring in real-time.
            - If 'account_id' is provided, the query filters results to only include identities from that AWS account.
        """
        filters = {"CIEM_Identities_Filter.PROVIDER": [
            {"value": cloud_provider, "filterGroup": "include"}]}
        if account_id:
            filters["CIEM_Identities_Filter.DOMAIN_ID"] = [
                {"value": account_id, "filterGroup": "include"}]
        timeout_time = time.time() + timeout_seconds
        update_completed = False
        while time.time() < timeout_time and not update_completed:
            response = self.query_identities(
                start_time_range, end_time_range, filters)
            if response.status_code == 200:
                response_json = response.json()
                logger.debug(f"Response JSON: {response_json}")
                records = response_json['data']
                for record in records:
                    name = record.get("NAME", "")
                    if owner in name:
                        update_completed = True
                        logger.info(
                            f"Identity update completed. Found the below record with NAME starting with '{owner}':\n{record}")
                        break
                if not update_completed:
                    logger.info(
                        f"Status code 200 received, but no record found with NAME start with '{owner}'. Sleeping for 60 seconds before retrying to check for idenetity update.")
                    time.sleep(60)
            elif response.status_code == 204:
                logger.info(
                    "Status code 204 received. Sleeping for 60 seconds before retrying to check for idenetity update.")
                time.sleep(60)
            else:
                logger.error(f"Unexpected status code: {
                             response.status_code} received. Sleeping for 2 seconds before retrying to check for idenetity update.")
                time.sleep(2)
            end_time_range = datetime_to_timestamp(datetime.now(timezone.utc))
        logger.info(f"Identity update status: {update_completed}")
        return update_completed

    def check_for_identity_properties_update(
        self,
        start_time_range: int,
        end_time_range: int,
        owner: str,
        cloud_provider: str,
        account_id: str,
        timeout_seconds: int = 60
    ) -> bool:
        """
        Wait for the identity properties update to complete within the specified timeout.

        This method continuously queries the API for identity updates within the given time range.
        It verifies whether at least one record exists where:
        - 'NAME' starts with the specified 'owner'.
        - 'PROPERTIES' is **not null**.

        The 'end_time_range' is dynamically updated to the current UTC time at each iteration, ensuring that
        the search window extends to include any newly updated identity records.

        Args:
            start_time_range (int): Start timestamp in milliseconds.
            end_time_range (int): End timestamp in milliseconds.
            owner (str): The prefix used to identify resources that should be present post-update.
            cloud_provider (str): Cloud provider name used for filtering.
            account_id (str): AWS account ID used for filtering.
            timeout_seconds (int, optional): Maximum time (in seconds) to wait for the update (default: 60).

        Returns:
            bool: True if at least one identity has non-null "PROPERTIES" within the timeout, False otherwise.

        Note:
            - Filters identities based on:
            - Cloud provider
            - Account ID
            - NAME field (which should start with 'owner')
            - The 'end_time_range' is updated to the current time in each iteration.
            - If 'account_id' is provided, the query filters results to only include identities from that AWS account.
        """
        filters = {
            "CIEM_Identities_Filter.PROVIDER": [{"value": cloud_provider, "filterGroup": "include"}],
            # Wildcard filtering
            "CIEM_Identities_Filter.NAME": [{"value": f"{owner}*", "filterGroup": "include"}],
            "CIEM_Identities_Filter.DOMAIN_ID": [{"value": account_id, "filterGroup": "include"}]
        }

        timeout_time = time.time() + timeout_seconds
        update_completed = False

        while time.time() < timeout_time and not update_completed:
            response = self.query_identities(
                start_time_range, end_time_range, filters)

            if response.status_code == 200:
                response_json = response.json()
                logger.debug(f"Response JSON: {response_json}")
                records = response_json.get('data', [])

                for record in records:
                    name = record.get("NAME", "")
                    properties = record.get("PROPERTIES", None)

                    if properties:  # Ensure "PROPERTIES" is not null
                        update_completed = True
                        logger.info(
                            f"Identity properties update completed. Found record with NAME '{name}' and non-null PROPERTIES:\n{record}")
                        break

                if not update_completed:
                    logger.info(
                        f"Status code 200 received, but no record found with NAME starting with '{owner}' that has non-null PROPERTIES. "
                        f"Sleeping for 60 seconds before retrying."
                    )
                    time.sleep(60)

            elif response.status_code == 204:
                logger.info(
                    "Status code 204 received. Sleeping for 60 seconds before retrying.")
                time.sleep(60)

            else:
                logger.error(
                    f"Unexpected status code: {response.status_code} received. Sleeping for 2 seconds before retrying.")
                time.sleep(2)

            # Update end_time_range to current UTC time
            end_time_range = datetime_to_timestamp(datetime.now(timezone.utc))

        logger.info(f"Identity properties update status: {update_completed}")
        return update_completed
