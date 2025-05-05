import pytest
import time
from datetime import datetime, timedelta, timezone
from fortiqa.libs.helper.date_helper import datetime_to_timestamp, timestamp_to_iso
from fortiqa.libs.lw.apiv1.api_client.identity.identity import IdentityV1
from fortiqa.libs.helper.general_helper import select_random_from_list
import logging


logger = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def time_filter():
    """Fixture to generate a time filter for use in tests.

    This fixture returns a dictionary containing 'StartTimeRange' and 'EndTimeRange' keys.
    - 'StartTimeRange' is set to **7 days before** the current UTC time.
    - 'EndTimeRange' is set to the **current UTC time**.
    - The timestamps are converted using 'datetime_to_timestamp'.

    Returns:
        dict: A dictionary containing 'StartTimeRange' and 'EndTimeRange' in timestamp format.

        Example:
        {
            "StartTimeRange": 1730457600000,  # Timestamp for 7 days ago
            "EndTimeRange": 1731062400000    # Timestamp for current time
        }
    """
    # Get the current time in UTC
    current_utc_time = datetime.now(timezone.utc)

    # Calculate the last day time by subtracting one day from the current time
    last_seven_day_utc_time = current_utc_time - timedelta(days=7)

    # Format the current time and the last day time in the desired format
    current_utc_time_timestamp = datetime_to_timestamp(current_utc_time)
    last_seven_day_utc_time_timestamp = datetime_to_timestamp(
        last_seven_day_utc_time)
    return {
        "StartTimeRange": last_seven_day_utc_time_timestamp,
        "EndTimeRange": current_utc_time_timestamp
    }


@pytest.fixture(scope="session")
def identity_v1_client(api_v1_client):
    """Provides an instance of IdentityV1 to interact with the Lacework Identity API.
    Given:
        - A  Lacework API  V1 client.
    Returns:
        - An IdentityV1 instance that can be used to make API calls.
    """
    return IdentityV1(api_v1_client)


@pytest.fixture(scope="session")
def list_all_identity(identity_v1_client, time_filter):
    """Calls the Lacework Identity API and retrieves identity data, with retries on failure.

    Given:
        - An IdentityV1 API client.
        - A time filter containing 'StartTimeRange' and 'EndTimeRange'.

    When:
        - Making an API request to fetch identities.

    Then:
        - If the response contains identity data, return it.
        - If the response is empty but status is 200, raise an error as data is expected.
        - If the API request fails (non-200 response), retry up to 3 times with a 30-second wait between attempts.
        - If all retries fail, raise an error with the final response details.

    Returns:
        dict: API response containing identity data.

    Raises:
        ValueError: If the API response is empty despite expecting data.
        ValueError: If all retries fail due to non-200 responses.
    """
    # Extract start and end time from time_filter fixture
    start_time_range = time_filter["StartTimeRange"]
    end_time_range = time_filter["EndTimeRange"]
    retry = 0
    while retry <= 3:
        logger.info(
            f"requesting identities data form  {timestamp_to_iso(start_time_range)} to {timestamp_to_iso(end_time_range)}")
        # Call the Identity API
        response = identity_v1_client.query_identities(
            start_time_range=start_time_range,
            end_time_range=end_time_range
        )

        # Ensure response status is 200
        if response.status_code == 200:
            data = response.json().get("data", [])

            # If data is present, return the full response
            if data:
                return data

            # If response is empty, return None
            if not data:
                raise ValueError(
                    f"API response returned an empty dataset, but identities data is expected "
                    f"from {timestamp_to_iso(start_time_range)} to {timestamp_to_iso(end_time_range)}."
                )
        else:
            # Log status code and response body for debugging
            logger.info(
                f"API request failed with status code: {response.status_code}")
            logger.info(f"Response Body: {response.text}")

            retry += 1
            if retry > 3:
                raise ValueError(
                    f"API request failed with status code: {response.status_code} , Response Body: {response.text}")
            logger.info(
                f"wiat for 30 seconds before retrying for the {retry} time")
            time.sleep(30)


@pytest.fixture(scope="session")
def list_all_accounts_or_projects(list_all_identity):
    """Extracts a unique list of accounts or projects from identity data.

    Given:
        - 'list_all_identity': API response containing identity data.

    When:
        - Extracting unique account or project identifiers based on the 'DOMAIN_ID' field.

    Then:
        - Returns a set of **all unique accounts or projects** found across identities.
        - If no accounts or projects exist, returns an **empty set**.

    Returns:
        set[str]: A set of all unique accounts or projects found in the API response.
    """
    if not list_all_identity:
        logger.info(
            "No identities found, returning an empty accounts/projects list.")
        return set()

    # Extract unique DOMAIN_ID values from the identity data
    accounts_or_projects = {identity.get(
        "DOMAIN_ID") for identity in list_all_identity if "DOMAIN_ID" in identity and identity["DOMAIN_ID"]}

    logger.info(f"Available accounts or projects: {accounts_or_projects}")

    return accounts_or_projects


@pytest.fixture(scope="session")
def list_all_cloud_providers(list_all_identity):
    """Extracts a unique set of 'PROVIDER' values from all identities.

    Given:
        - The 'list_all_identity' fixture which retrieves all identities.

    When:
        - Extracting unique 'PROVIDER' values from the response.

    Then:
        - If no identities exist, return an empty set.
        - If identities exist, return a set of unique cloud providers.

    Returns:
        set: A set of available cloud provider types.
    """
    if not list_all_identity:
        logger.info(
            "No identities found, returning an empty cloud provider list.")
        return set()

    # Extract unique provider types
    cloud_providers = {identity.get(
        "PROVIDER") for identity in list_all_identity if "PROVIDER" in identity}

    logger.info(f"Available Cloud Providers from API: {cloud_providers}")

    return cloud_providers


@pytest.fixture(scope="session")
def list_all_identity_aws(identity_v1_client, time_filter):
    """Calls the Lacework Identity API and retrieves only AWS identities.

    Given:
        - An IdentityV1 API client.
        - A time filter containing 'StartTimeRange' and 'EndTimeRange'.

    When:
        - Calling the Identity API with an AWS provider filter.

    Then:
        - If AWS identities are found, return them.
        - If no AWS identities are found, return None.
        - If the API call fails, log the error and fail the test.

    Returns:
        dict | None: API response containing only AWS identities, or None if none exist.
    """
    # Extract start and end time from time_filter fixture
    start_time_range = time_filter["StartTimeRange"]
    end_time_range = time_filter["EndTimeRange"]
    response = identity_v1_client.get_all_identity_by_cloud_provider(start_time_range=start_time_range,
                                                                     end_time_range=end_time_range,
                                                                     cloud_provider="AWS")
    # Ensure response status is 200
    if response.status_code == 200:
        data = response.json().get("data", [])
        # Return response if data exists
        if data:
            return data
        logger.info("No AWS identities found in the API response.")
        return None  # If no AWS identities are found, return None
    else:
        # Log status code and response body for debugging
        logger.info(
            f"API request failed with status code: {response.status_code}")
        logger.info(f"Response Body: {response.text}")

        # Fail pytest explicitly
        pytest.fail(
            f"API request failed! Status: {response.status_code}, Response: {response.text}")


@pytest.fixture(scope="session")
def list_all_identity_gcp(identity_v1_client, time_filter):
    """Calls the Lacework Identity API and retrieves only GCP identities.

    Given:
        - An IdentityV1 API client.
        - A time filter containing 'StartTimeRange' and 'EndTimeRange'.

    When:
        - Calling the Identity API with an GCP provider filter.

    Then:
        - If AWS identities are found, return them.
        - If no AWS identities are found, return None.
        - If the API call fails, log the error and fail the test.

    Returns:
        dict | None: API response containing only AWS identities, or None if none exist.
    """
    # Extract start and end time from time_filter fixture
    start_time_range = time_filter["StartTimeRange"]
    end_time_range = time_filter["EndTimeRange"]
    response = identity_v1_client.get_all_identity_by_cloud_provider(start_time_range=start_time_range,
                                                                     end_time_range=end_time_range,
                                                                     cloud_provider="GCP")
    # Ensure response status is 200
    if response.status_code == 200:
        data = response.json().get("data", [])

        # Return response if data exists
        if data:
            return data

        logger.info("No GCP identities found in the API response.")
        return None  # If no AWS identities are found, return None
    else:
        # Log status code and response body for debugging
        logger.info(
            f"API request failed with status code: {response.status_code}")
        logger.info(f"Response Body: {response.text}")

        # Fail pytest explicitly
        pytest.fail(
            f"API request failed! Status: {response.status_code}, Response: {response.text}")


@pytest.fixture(scope="session")
def list_all_identity_aws_types(list_all_identity_aws):
    """Extracts a list of unique 'IDENTITY_TYPE' values from AWS identities.

    Given:
        - The 'list_all_identity_aws' fixture which retrieves AWS identities.

    When:
        - Extracting unique 'IDENTITY_TYPE' values from the response.

    Then:
        - If no AWS identities exist, return an empty list.
        - If AWS identities exist, return a list of unique identity types.

    Returns:
        list: A list of available identity types for AWS.
    """
    # If no AWS identities exist, return an empty list
    if not list_all_identity_aws:
        logger.info(
            "No AWS identities found, returning an empty identity type list.")
        return []

    # Extract unique identity types
    identity_types = list(
        {identity.get("IDENTITY_TYPE")
         for identity in list_all_identity_aws if "IDENTITY_TYPE" in identity}
    )

    logger.info(f"Available AWS identity types: {identity_types}")
    return identity_types


@pytest.fixture(scope="session")
def list_all_identity_types(list_all_identity):
    """Extracts a unique set of 'IDENTITY_TYPE' values from all identities.

    Given:
        - The 'list_all_identity' fixture which retrieves all identities.

    When:
        - Extracting unique 'IDENTITY_TYPE' values from the response.

    Then:
        - If no identities exist, return an empty set.
        - If identities exist, return a set of unique identity types.

    Returns:
        set: A set of available identity types.
    """
    # If no identities exist, return an empty list
    if not list_all_identity:
        logger.info(
            "No identities found, returning an empty identity type list.")
        return []

    # Extract unique identity types
    identity_types = {identity.get(
        "IDENTITY_TYPE") for identity in list_all_identity if "IDENTITY_TYPE" in identity}

    logger.info(f"Available Identity Types from API: {identity_types}")

    return identity_types


@pytest.fixture(scope="session")
def list_all_risks(list_all_identity):
    """Fetch a unique set of risk types found in the API response.

    Given:
        - 'list_all_identity': API response containing identity data.

    When:
        - Extracting all unique risk types from the 'PROPERTIES' field of identities.

    Then:
        - Returns a set of **all risk types found** across identities.
        - If no risks exist, returns an **empty set**.

    Returns:
        set[str]: A set of all unique risk types found in the API response.
    """
    if not list_all_identity:
        logger.info("No identities found, returning an empty risk list.")
        return []

    # Extract all unique risk keys from the "PROPERTIES" field across all identities
    risks = set()
    for identity in list_all_identity:
        properties = identity.get("PROPERTIES")
        if properties is not None:
            risks.update(properties.keys())

    # Convert to sorted list for consistency

    logger.info(f"Available risks from API response: {risks}")

    return risks


@pytest.fixture(scope="session")
def list_all_risk_severities(list_all_identity):
    """Fetch a unique set of risk severities found in the API response.

    Given:
        - 'list_all_identity': API response containing identity data.

    When:
        - Extracting all unique risk severities from the 'RISK_SEVERITY' field of identities.

    Then:
        - Returns a set of **all risk severities found** across identities.
        - If no risk severities exist, returns an **empty set**.

    Returns:
        set[str]: A set of all unique risk severities found in the API response.
    """
    if not list_all_identity:
        logger.info(
            "No identities found, returning an empty risk severity list.")
        return set()

    # Extract all unique risk severities from the "RISK_SEVERITY" field across all identities
    risk_severities = {
        identity.get("RISK_SEVERITY") for identity in list_all_identity if identity.get("RISK_SEVERITY")
    }

    logger.info(
        f"Available risk severities from API response: {risk_severities}")
    return risk_severities


@pytest.fixture(scope="function")
def random_identity(list_all_identity):
    """Selects a random identity record from the list of all identities.

    Given:
        - 'list_all_identity': A list of all identities retrieved from the API.

    When:
        - Selecting a random identity record from the list.

    Then:
        - If no identities are available, log the issue and return None.
        - Otherwise, return a randomly selected identity record.

    Returns:
        dict | None: A randomly selected identity record, or None if no identities are available.
    """
    return select_random_from_list(list_all_identity, description="identity record")


@pytest.fixture(scope="function")
def random_identity_with_entitlements(list_all_identity):
    """Selects a random identity record from the list of all identities that have entitlements.

    Given:
        - 'list_all_identity': A list of all identities retrieved from the API.

    When:
        - Filtering identities where 'ENTITLEMENTS_COUNT' is **greater than or equal to 1**.
        - Selecting a random identity record from the filtered list.

    Then:
        - If no identities with entitlements are available, log the issue and return None.
        - Otherwise, return a randomly selected identity record.

    Returns:
        dict | None: A randomly selected identity record with entitlements, or None if no such identities are available.
    """
    # Filter identities with entitlements
    identities_with_entitlements = [
        identity for identity in list_all_identity
        if int(identity.get("ENTITLEMENTS_COUNT", "0")) >= 1
    ]

    return select_random_from_list(identities_with_entitlements, description="identity record with entitlements")


@pytest.fixture(scope="session")
def select_identity_tags(list_all_identity):
    """Selects tags from an identity record in 'list_all_identity'.

    Given:
        - The 'list_all_identity' fixture, which retrieves all identities.

    When:
        - Iterating through the list to find an identity with tags.

    Then:
        - If an identity has tags, return them.
        - If no identity has tags, return None.

    Returns:
        dict | None: A dictionary containing tags from an identity or None if no tags are found.

    Args:
        list_all_identity (list): A list of identity records retrieved from the API.
    """
    if not list_all_identity:
        logger.info("No identities found in API response.")
        return None

    for identity in list_all_identity:
        tags = identity.get("TAGS")
        if tags:  # Ensure tags exist and are not an empty dictionary
            logger.info(f"Selected identity with tags: {tags}")
            return tags

    logger.info("No identities with tags found.")
    return None


@pytest.fixture(scope="session")
def find_up_to_three_access_key_records(list_all_identity):
    """Find up to three records with at least one access key.

    Given:
        - The 'list_all_identity' fixture containing all identity records.

    When:
        - Iterating through identities to find those with 'ACCESS_KEYS'.

    Then:
        - Return a list of up to three records, each containing a single access key.
        - If fewer than three are found, return available records.
        - If no records with access keys exist, return None.

    Returns:
        list[dict] | None: A list of records with access keys, or None if no records have access keys.

    Args:
        list_all_identity (list): A list of identity records from the Lacework API.
    """
    access_key_records = []

    for identity in list_all_identity:
        access_keys = identity.get("ACCESS_KEYS", {})

        if access_keys:
            # Extract only one access key from the dictionary
            first_access_key = next(iter(access_keys.keys()))
            access_key_records.append({
                "PRINCIPAL_ID": identity.get("PRINCIPAL_ID"),
                "ACCESS_KEY": first_access_key
            })

        if len(access_key_records) == 3:
            break  # Stop when three records are found

    if not access_key_records:
        logger.info("No records with access keys found.")
        return None

    logger.info(
        f"Found {len(access_key_records)} records with access keys: {access_key_records}")
    return access_key_records


@pytest.fixture(scope="session")
def entitlement_unused_distribution(list_all_identity):
    """Computes the distribution of identities across entitlement unused quartiles dynamically.

    Given:
        - 'list_all_identity': A list of all identities retrieved from the API.

    When:
        - Extracting and categorizing identities based on their 'ENTITLEMENTS_UNUSED_QUARTILE'.

    Then:
        - **Only adds quartiles found in the dataset** as keys in the dictionary.
        - Each key maps to a nested dictionary containing:
            - '"quartile"': The quartile value ('0', '1', '2', '3').
            - '"count"': Number of identities in that quartile.
        - If **no records exist** for any quartile, the fixture **returns an empty dictionary**.

    Returns:
        dict[str, dict[str, int]]: A dictionary mapping entitlement unused quartile categories
        to their quartile value and count.

    Example:
        {
            "unused_entitlement_0-24%": {"quartile": "0", "count": 5},
            "unused_entitlement_50-74%": {"quartile": "2", "count": 2}
        }
    """
    quartile_mapping = {
        "0": "unused_entitlement_0-24%",
        "1": "unused_entitlement_25-49%",
        "2": "unused_entitlement_50-74%",
        "3": "unused_entitlement_75-100%",
    }

    entitlement_counts = {}

    for identity in list_all_identity:
        quartile = str(identity.get("ENTITLEMENTS_UNUSED_QUARTILE", ""))
        if quartile in quartile_mapping:
            key = quartile_mapping[quartile]
            if key not in entitlement_counts:
                entitlement_counts[key] = {
                    "quartile": quartile, "count": 0}  # Initialize count

            entitlement_counts[key]["count"] += 1  # Increment count

    logger.info(
        f"Computed entitlement unused distribution: {entitlement_counts}")

    return entitlement_counts


@pytest.fixture(scope="session")
def entitlement_used_distribution(list_all_identity):
    """Computes the distribution of identities across entitlement used quartiles dynamically.

    Given:
        - 'list_all_identity': A list of all identities retrieved from the API.

    When:
        - Extracting and categorizing identities based on their 'ENTITLEMENTS_USED_QUARTILE'.

    Then:
        - **Only adds quartiles found in the dataset** as keys in the dictionary.
        - Each key maps to a nested dictionary containing:
            - '"quartile"': The quartile value ('0', '1', '2', '3').
            - '"count"': Number of identities in that quartile.
        - If **no records exist** for any quartile, the fixture **returns an empty dictionary**.

    Returns:
        dict[str, dict[str, int]]: A dictionary mapping entitlement used quartile categories
        to their quartile value and count.

    Example:
        {
            "used_entitlement_0-24%": {"quartile": "0", "count": 10},
            "used_entitlement_50-74%": {"quartile": "2", "count": 4}
        }
    """
    quartile_mapping = {
        "0": "used_entitlement_0-24%",
        "1": "used_entitlement_25-49%",
        "2": "used_entitlement_50-74%",
        "3": "used_entitlement_75-100%",
    }

    entitlement_counts = {}

    for identity in list_all_identity:
        quartile = str(identity.get("ENTITLEMENTS_USED_QUARTILE", ""))
        if quartile in quartile_mapping:
            key = quartile_mapping[quartile]
            if key not in entitlement_counts:
                entitlement_counts[key] = {
                    "quartile": quartile, "count": 0}  # Initialize count

            entitlement_counts[key]["count"] += 1  # Increment count

    logger.info(
        f"Computed entitlement used distribution: {entitlement_counts}")

    return entitlement_counts
