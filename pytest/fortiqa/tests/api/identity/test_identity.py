import pytest
import logging

logger = logging.getLogger(__name__)

# List of all possible identity types
ALL_IDENTITY_TYPES = [
    "AWS_GROUP",
    "AWS_IDENTITYSTORE_GROUP",
    "AWS_IDENTITYSTORE_USER",
    "AWS_INSTANCE_PROFILE",
    "AWS_ROLE",
    "AWS_ROOT_USER",
    "AWS_SERVICE",
    "AWS_SERVICE_LINKED_ROLE",
    "AWS_USER",
    "GCP_SERVICE_ACCOUNT",
    "GCP_GOOGLE_GROUP",
    "GCP_GOOGLE_ACCOUNT"
]
ALL_RISKS = [
    "UNUSED_180DAYS_FULL_ADMIN",
    "UNUSED_180DAYS_IAM_WRITE",
    "AWS_ROOT_USER_PASSWORD_LOGIN_NO_MFA",
    "AWS_ROOT_USER_ACCESS_KEY",
    "HARDCODED_ACTIVE_ACCESS_KEY_FULL_ADMIN",
    "HARDCODED_ACTIVE_ACCESS_KEY_IAM_WRITE",
    "EXPOSURE_PUBLIC_FULL_ADMIN",
    "EXPOSURE_PUBLIC_IAM_WRITE",
    "ALLOWS_FULL_ADMIN",
    "ALLOWS_IAM_WRITE",
    "PASSWORD_LOGIN_NO_MFA",
    "HARDCODED_ACTIVE_ACCESS_KEY",
    "EXPOSURE_PUBLIC",
    "ALLOWS_RESOURCE_EXPOSURE",
    "ALLOWS_CREDENTIAL_EXPOSURE",
    "ALLOWS_CONTAINERIZATION",
    "ALLOWS_NETWORKING",
    "ALLOWS_MONITORING",
    "ALLOWS_MACHINE_LEARNING",
    "ALLOWS_DATA_PROCESSING",
    "ALLOWS_SECURITY",
    "ALLOWS_MANAGEMENT",
    "ALLOWS_MESSAGING",
    "ALLOWS_SECRETS_READ",
    "ALLOWS_STORAGE_WRITE",
    "ALLOWS_COMPUTE_EXECUTE",
    "ALLOWS_PRIVILEGE_PASSING",
    "HARDCODED_INACTIVE_ACCESS_KEY",
    "ALLOWS_STORAGE_READ",
    "UNUSED_180DAYS_ACTIVE_ACCESS_KEY",
    "UNUSED_180DAYS_USER",
    "INACTIVE_ACCESS_KEY",
    "EXPOSURE_SINGLE_PRINCIPAL",
    "HARDCODED_ACCESS_KEY",
    "DISABLED_WITH_ALLOWS_FULL_ADMIN",
    "DISABLED_WITH_ALLOWS_IAM_WRITE",
    "DISABLED_WITH_ALLOWS_CREDENTIAL_EXPOSURE",
    "DISABLED_WITH_ALLOWS_RESOURCE_EXPOSURE",
    "DISABLED_WITH_ALLOWS_SECRETS_READ",
    "DISABLED_WITH_ALLOWS_STORAGE_WRITE",
    "DISABLED_WITH_ALLOWS_COMPUTE_EXECUTE",
    "DISABLED_WITH_ALLOWS_PRIVILEGE_PASSING",
    "DISABLED_WITH_ALLOWS_STORAGE_READ",
    "DISABLED_WITH_ALLOWS_CONTAINERIZATION",
    "DISABLED_WITH_ALLOWS_NETWORKING",
    "DISABLED_WITH_ALLOWS_MONITORING",
    "DISABLED_WITH_ALLOWS_MACHINE_LEARNING",
    "DISABLED_WITH_ALLOWS_DATA_PROCESSING",
    "DISABLED_WITH_ALLOWS_SECURITY",
    "DISABLED_WITH_ALLOWS_MANAGEMENT",
    "DISABLED_WITH_ALLOWS_MESSAGING",
    "AI_READ",
    "AI_WRITE",
]
ALL_RISK_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
UNUSED_ENTITLEMENT = [
    "unused_entitlement_0-24%",
    "unused_entitlement_25-49%",
    "unused_entitlement_50-74%",
    "unused_entitlement_75-100%"
]
USED_ENTITLEMENT = [
    "used_entitlement_0-24%",
    "used_entitlement_25-49%",
    "used_entitlement_50-74%",
    "used_entitlement_75-100%"
]
CLOUD_PROVIDERS = ["AWS", "GCP"]


def test_detect_new_identity_types_in_api_response(list_all_identity_types):
    """Verify that all identity types in the API response are included in 'ALL_IDENTITY_TYPES'.

    Given:
        - A static list of expected identity types ('ALL_IDENTITY_TYPES').
        - The 'list_all_identity_types' fixture retrieving all available identity types from the API.

    When:
        - Comparing API identity types against the static list.

    Then:
        - If any identity type is **missing** from 'ALL_IDENTITY_TYPES', **fail the test**.
        - If all types are accounted for, log success.

    Args:
        list_all_identity_types (set): Set of identity types found in the API response.
    """
    logger.info(f"Expected identity types: {ALL_IDENTITY_TYPES}")
    logger.info(f"API response identity types: {list_all_identity_types}")

    # Identify any missing identity types not present in ALL_IDENTITY_TYPES
    missing_identity_types = list_all_identity_types - set(ALL_IDENTITY_TYPES)

    # Fail test if any new identity types are detected
    assert not missing_identity_types, (
        f"Test failed: New identity types detected in API response: {missing_identity_types}. "
        "Update 'ALL_IDENTITY_TYPES' constant accordingly."
    )

    # Log success if everything matches
    logger.info(
        "Test passed: All API identity types are accounted for in 'ALL_IDENTITY_TYPES'.")


def test_detect_new_risks_in_api_response(list_all_risks):
    """Verify that all risks in the API response are included in 'ALL_RISKS'.

    Given:
        - A static list of expected risks ('ALL_RISKS').
        - The 'list_all_risks' fixture retrieving all available risks from the API.

    When:
        - Comparing API risks against the static list.

    Then:
        - If any risk is **missing** from 'ALL_RISKS', **fail the test**.
        - If all risks are accounted for, log success.

    Args:
        list_all_risks (set): Set of risks found in the API response.
    """
    logger.info(f"Expected risks: {ALL_RISKS}")
    logger.info(f"API response risks: {list_all_risks}")

    # Identify any missing risks not present in ALL_RISKS
    missing_risks = list_all_risks - set(ALL_RISKS)

    # Fail test if any new risks are detected
    assert not missing_risks, (
        f"Test failed: New risks detected in API response: {missing_risks}. "
        "Update 'ALL_RISKS' constant accordingly."
    )

    # Log success if everything matches
    logger.info("Test passed: All API risks are accounted for in 'ALL_RISKS'.")


@pytest.mark.parametrize("cloud_provider", CLOUD_PROVIDERS)
def test_filter_identity_by_provider_returns_only_identity_from_specified_provider(
    identity_v1_client, cloud_provider, list_all_cloud_providers, time_filter
):
    """Verify filtering by 'PROVIDER' returns only identities containing the specified provider.

    Given:
        - A list of all possible cloud providers ('CLOUD_PROVIDERS').
        - The API client for identity queries.
        - A valid time filter for the query.
        - The 'list_all_cloud_providers' fixture containing available cloud providers.

    When:
        - Filtering the API response by 'PROVIDER'.

    Then:
        - If the provider is **not found** in 'list_all_cloud_providers', **skip** the test.
        - Otherwise, ensure the API returns **status code 200**.
        - Verify that **all returned identities have the requested provider**.
        - If no data is returned, **fail the test**, since identities with that provider exist.

    Args:
        identity_v1_client (IdentityV1): API client for identity queries.
        cloud_provider (str): The cloud provider being tested (e.g., "AWS", "GCP").
        list_all_cloud_providers (set): A set of cloud providers found in the API response.
        time_filter (dict): Time range filter for the API query.
    """
    logger.info(
        f"Test execution - Available cloud providers: {list_all_cloud_providers}")
    logger.info(f"Testing cloud provider: {cloud_provider}")

    # Skip if the cloud provider is not found in API response
    if cloud_provider not in list_all_cloud_providers:
        pytest.skip(
            f"Skipping test as no data is available for cloud provider: {cloud_provider}")

    # Make API call
    response = identity_v1_client.get_all_identity_by_cloud_provider(
        start_time_range=time_filter["StartTimeRange"],
        end_time_range=time_filter["EndTimeRange"],
        cloud_provider=cloud_provider
    )

    # Ensure API call is successful
    assert response.status_code == 200, (
        f"API request failed for provider={cloud_provider}. "
        f"Status: {response.status_code}, Response: {response.text}"
    )

    # Log API response
    logger.info(f"API Response: {response.json()}")

    # Extract response data
    data = response.json().get("data", [])

    # **Fail the test** if no identities were returned
    assert data, f"Test failed: Expected identities for provider '{cloud_provider}', but API returned no data."

    # Verify that all returned identities match the requested provider
    mismatched_identities = [
        identity for identity in data if identity.get("PROVIDER") != cloud_provider]

    assert not mismatched_identities, (
        f"Test failed: Found identities with incorrect provider when filtering for '{cloud_provider}': "
        f"{mismatched_identities}"
    )

    # Log number of returned identities for visibility
    logger.info(
        f"Test passed: {len(data)} identities with provider '{cloud_provider}' were returned successfully.")


@pytest.mark.parametrize("identity_type", ALL_IDENTITY_TYPES)
def test_filtered_identity_by_identity_TYPE_returns_only_identity_containing_the_specified_type(
    identity_v1_client, identity_type, time_filter, list_all_identity_types
):
    """Verify filtering by 'IDENTITY_TYPE' returns only identities containing the specified type.

    Given:
        - A list of all possible identity types.
        - The API client for identity queries.
        - A valid time filter for the query.

    When:
        - Filtering the API response by 'IDENTITY_TYPE'.

    Then:
        - If the identity type is **not found** in 'list_all_identity_types', **skip** the test.
        - Otherwise, ensure the API returns **status code 200**.
        - Verify that **all returned identities have the requested identity type**.
        - If no data is returned, **fail the test**, since identities of that type exist.

    Args:
        identity_v1_client (IdentityV1): The API client used for identity queries.
        identity_type (str): The identity type being tested.
        time_filter (dict): A dictionary containing 'StartTimeRange' and 'EndTimeRange' timestamps.
        list_all_identity_types (list[str]): A list of available identity types retrieved from the API.
    """
    logger.info(
        f"Test execution - Available identity types: {list_all_identity_types}")
    logger.info(f"Testing identity type: {identity_type}")
    # Check if the identity type exists in Lacework data, otherwise skip
    if identity_type not in list_all_identity_types:
        pytest.skip(
            f"Skipping test as no data is available for identity type: {identity_type}")

    # Construct API filter
    type_filter = {
        "CIEM_Identities_Filter.IDENTITY_TYPE": [
            {"value": identity_type, "filterGroup": "include"}
        ]
    }

    # Make API call
    response = identity_v1_client.query_identities(
        start_time_range=time_filter["StartTimeRange"],
        end_time_range=time_filter["EndTimeRange"],
        filters=type_filter
    )

    # Ensure API call is successful
    assert response.status_code == 200, f"API request failed for IDENTITY_TYPE={identity_type}. Status: {response.status_code}, Response: {response.text}"

    # Extract response data
    data = response.json().get("data", [])

    # **Fail the test** if no identities were returned (since we expect data)
    assert data, f"Test failed: Expected identities of type '{identity_type}', but API returned no data."

    # Verify all identities in the response match the requested identity type
    mismatched_identities = [
        identity for identity in data if identity.get("IDENTITY_TYPE") != identity_type
    ]

    assert not mismatched_identities, f"Found identities with incorrect type when filtering for '{identity_type}': {mismatched_identities}"

    # Log number of returned identities for visibility
    logger.info(
        f" Test passed: {len(data)} identities of type '{identity_type})' were returned.")


@pytest.mark.parametrize("risk", ALL_RISKS)
def test_filtered_identity_by_risk_returns_only_identity_containing_the_specified_risk(
    identity_v1_client, risk, time_filter, list_all_risks
):
    """Verify filtering by 'RISK' returns only identities containing the specified risk.

    Given:
        - A list of all possible risks.
        - The API client for identity queries.
        - A valid time filter for the query.

    When:
        - Filtering the API response by 'RISK' using "CIEM_Identities_Filter.PROPERTIES_ARRAY".

    Then:
        - If the risk is **not found** in 'list_all_risks', **skip** the test.
        - Otherwise, ensure the API returns **status code 200**.
        - Verify that **all returned identities contain the requested risk**.
        - If no data is returned, **fail the test**, since identities with that risk exist.

    Args:
        identity_v1_client (IdentityV1): The API client used for identity queries.
        risk (str): The risk type being tested.
        time_filter (dict): A dictionary containing 'StartTimeRange' and 'EndTimeRange' timestamps.
        list_all_risks (set[str]): A set of available risk types retrieved from the API.
    """
    logger.info(f"Test execution - Available identity types: {list_all_risks}")
    logger.info(f"Testing identity type: {risk}")
    # Check if the risk exists in Lacework data, otherwise skip
    if risk not in list_all_risks:
        pytest.skip(f"Skipping test as no data is available for risk: {risk}")

    # Construct API filter for risk
    risk_filter = {
        "CIEM_Identities_Filter.PROPERTIES_ARRAY": [
            {"value": risk, "filterGroup": "include"}
        ]
    }

    # Make API call
    response = identity_v1_client.query_identities(
        start_time_range=time_filter["StartTimeRange"],
        end_time_range=time_filter["EndTimeRange"],
        filters=risk_filter
    )

    # Ensure API call is successful
    assert response.status_code == 200, f"API request failed for RISK={risk}. Status: {response.status_code}, Response: {response.text}"

    # Extract response data
    data = response.json().get("data", [])

    # **Fail the test** if no identities were returned (since we expect data)
    assert data, f"Test failed: Expected identities with risk '{risk}', but API returned no data."

    # Verify all identities in the response contain the requested risk
    mismatched_identities = [
        identity for identity in data if risk not in identity.get("PROPERTIES", {})
    ]

    assert not mismatched_identities, f"Found identities that do not have the expected risk '{risk}': {mismatched_identities}"

    # Log number of returned identities for visibility
    logger.info(
        f"Test passed: {len(data)} identities with risk '{risk}' were returned successfully.")


@pytest.mark.parametrize(
    "risk_severity",
    [
        pytest.param(severity, marks=pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/PSP-3156"))
        if severity != "CRITICAL" else pytest.param(severity)
        for severity in ALL_RISK_SEVERITIES
    ]
)
def test_filtered_identity_by_risk_severity_returns_only_identity_with_specified_severity(
    identity_v1_client, risk_severity, time_filter, list_all_risk_severities
):
    """Verify filtering by 'RISK_SEVERITY' returns only identities with the specified severity.

    Given:
        - A list of all possible risk severities extracted from 'list_all_identity'.
        - The API client for identity queries.
        - A valid time filter for the query.

    When:
        - Filtering the API response by 'RISK_SEVERITY'.

    Then:
        - If the risk severity is **not found** in 'list_all_risk_severities', **skip** the test.
        - Otherwise, ensure the API returns **status code 200**.
        - Verify that **all returned identities have the requested risk severity**.
        - If no data is returned, **fail the test**, since identities with that severity are expected.

    Args:
        identity_v1_client (IdentityV1): The API client used for identity queries.
        risk_severity (str): The risk severity being tested.
        time_filter (dict): A dictionary containing 'StartTimeRange' and 'EndTimeRange' timestamps.
        list_all_risk_severities (set[str]): A set of available risk severities retrieved from the API.
    """
    logger.info(
        f"Test execution - Available risk severities: {list_all_risk_severities}")
    logger.info(f"Testing risk severity: {risk_severity}")

    # Skip if the risk severity is not found in the API response
    if risk_severity not in list_all_risk_severities:
        pytest.skip(
            f"Skipping test as no data is available for risk severity: {risk_severity}")

    # Construct API filter
    severity_filter = {
        "CIEM_Identities_Filter.RISK_SEVERITY": [
            {"value": risk_severity, "filterGroup": "include"}
        ]
    }

    # Make API call
    response = identity_v1_client.query_identities(
        start_time_range=time_filter["StartTimeRange"],
        end_time_range=time_filter["EndTimeRange"],
        filters=severity_filter
    )

    # Ensure API call is successful
    assert response.status_code == 200, (
        f"API request failed for RISK_SEVERITY={risk_severity}. "
        f"Status: {response.status_code}, Response: {response.text}"
    )

    # Extract response data
    data = response.json().get("data", [])

    # **Fail the test** if no identities were returned (since we expect data)
    assert data, f"Test failed: Expected identities with risk severity '{risk_severity}', but API returned no data."

    # Verify all identities in the response match the requested risk severity
    mismatched_identities = [
        identity for identity in data if identity.get("RISK_SEVERITY") != risk_severity
    ]

    assert not mismatched_identities, (
        f"Found identities with incorrect risk severity when filtering for '{risk_severity}': "
        f"{mismatched_identities}"
    )

    # Log number of returned identities for visibility
    logger.info(
        f"Test passed: {len(data)} identities with risk severity '{risk_severity}' were returned successfully.")


def test_filtered_identity_by_account_or_project_returns_only_matching_records(
    identity_v1_client, time_filter, list_all_accounts_or_projects
):
    """Verify filtering by 'DOMAIN_ID' returns only identities belonging to the specified account or project.

    Args:
        identity_v1_client (IdentityV1): The API client for identity queries.
        time_filter (dict): Time range filter for the API query.
        list_all_accounts_or_projects (set[str]): Set of all available accounts or projects.

    Given:
        - A set of all possible accounts or projects extracted from 'list_all_identity'.
        - The API client for identity queries.
        - A valid time filter for the query.

    When:
        - Filtering the API response by 'DOMAIN_ID'.

    Then:
        - Ensure the API returns **status code 200** for each account/project.
        - Verify that **all returned identities belong to the requested account or project**.
        - If no data is returned for an account/project, collect failures.
        - Log success for accounts/projects that pass validation.
    """
    failures = []

    for account_id in list_all_accounts_or_projects:
        logger.info(f"Testing filtering by account/project: {account_id}")

        # Construct API filter
        account_filter = {
            "CIEM_Identities_Filter.DOMAIN_ID": [
                {"value": account_id, "filterGroup": "include"}
            ]
        }

        # Make API call
        response = identity_v1_client.query_identities(
            start_time_range=time_filter["StartTimeRange"],
            end_time_range=time_filter["EndTimeRange"],
            filters=account_filter
        )

        # Ensure API call is successful
        if response.status_code != 200:
            failures.append(
                f"API request failed for DOMAIN_ID={account_id}. "
                f"Status: {response.status_code}, Response: {response.text}"
            )
            continue

        # Extract response data
        data = response.json().get("data", [])

        # **Fail the test** if no identities were returned (since we expect data)
        if not data:
            failures.append(
                f"Expected identities with DOMAIN_ID '{account_id}', but API returned no data.")
            continue

        # Verify all identities in the response match the requested account ID
        mismatched_identities = [
            identity for identity in data if identity.get("DOMAIN_ID") != account_id
        ]

        if mismatched_identities:
            failures.append(
                f"Found identities with incorrect DOMAIN_ID when filtering for '{account_id}': {mismatched_identities}"
            )
            continue

        # Log success
        logger.info(
            f"Test passed: {len(data)} identities found for DOMAIN_ID '{account_id}'.")

    # If any failures occurred, assert and log them
    if failures:
        failure_message = "\n".join(failures)
        pytest.fail(
            f"Test failed for one or more accounts/projects:\n{failure_message}")


def test_filtering_identity_by_principal_name_returns_only_identity_with_the_specified_name(
    identity_v1_client, random_identity, time_filter
):
    """Verify filtering by 'NAME' returns only identities containing the specified principal name.

    Given:
        - A randomly selected identity record from 'random_identity'.
        - The API client for identity queries.
        - A valid time filter for the query.

    When:
        - Filtering the API response by 'NAME'.

    Then:
        - Ensure the API returns **status code 200**.
        - Verify that **all returned identities have the requested principal name**.
        - If no data is returned, **fail the test**, since an identity with that name exists.
     Args:
        identity_v1_client (IdentityV1): API client instance for querying identities.
        random_identity (dict | None): A randomly selected identity record.
        time_filter (dict): A dictionary containing 'StartTimeRange' and 'EndTimeRange'.
    """
    if random_identity is None:
        pytest.skip(
            "Skipping test as no identities are available for random selection.")

    principal_name = random_identity.get("NAME")
    if not principal_name:
        pytest.skip(
            "Skipping test as selected identity does not have a 'NAME' field.")

    logger.info(f"Testing filtering by principal name: {principal_name}")

    # Construct API filter
    name_filter = {
        "CIEM_Identities_Filter.NAME": [
            {"value": principal_name, "filterGroup": "include"}
        ]
    }

    # Make API call
    response = identity_v1_client.query_identities(
        start_time_range=time_filter["StartTimeRange"],
        end_time_range=time_filter["EndTimeRange"],
        filters=name_filter
    )

    # Ensure API call is successful
    assert response.status_code == 200, (
        f"API request failed for principal name={principal_name}. "
        f"Status: {response.status_code}, Response: {response.text}"
    )

    # Extract response data
    data = response.json().get("data", [])

    # **Fail the test** if no identities were returned (since we expect data)
    assert data, f"Test failed: Expected identities with principal name '{principal_name}', but API returned no data."

    # Verify all identities in the response match the requested principal name
    mismatched_identities = [
        identity for identity in data if identity.get("NAME") != principal_name
    ]

    assert not mismatched_identities, (
        f"Found identities with incorrect principal name when filtering for '{principal_name}': "
        f"{mismatched_identities}"
    )

    # Log number of returned identities for visibility
    logger.info(
        f"Test passed: {len(data)} identities with principal name '{principal_name}' were returned successfully."
    )


def test_filtering_identity_by_principal_id_returns_only_identity_with_the_specified_id(
    identity_v1_client, random_identity, time_filter
):
    """Verify filtering by 'PRINCIPAL_ID' returns exactly one identity with the specified principal ID.

    Given:
        - A randomly selected identity record from 'random_identity'.
        - The API client for identity queries.
        - A valid time filter for the query.

    When:
        - Filtering the API response by 'PRINCIPAL_ID'.

    Then:
        - Ensure the API returns **status code 200**.
        - Verify that **exactly one identity** is returned in the response.
        - Ensure that **the returned identity has the requested principal ID**.
    Args:
        identity_v1_client (IdentityV1): API client instance for querying identities.
        random_identity (dict | None): A randomly selected identity record.
        time_filter (dict): A dictionary containing 'StartTimeRange' and 'EndTimeRange'.
    """
    if random_identity is None:
        pytest.skip(
            "Skipping test as no identities are available for random selection.")

    principal_id = random_identity.get("PRINCIPAL_ID")
    if not principal_id:
        pytest.skip(
            "Skipping test as selected identity does not have a 'PRINCIPAL_ID' field.")

    logger.info(f"Testing filtering by principal ID: {principal_id}")

    # Construct API filter
    id_filter = {
        "CIEM_Identities_Filter.PRINCIPAL_ID": [
            {"value": principal_id, "filterGroup": "include"}
        ]
    }

    # Make API call
    response = identity_v1_client.query_identities(
        start_time_range=time_filter["StartTimeRange"],
        end_time_range=time_filter["EndTimeRange"],
        filters=id_filter
    )

    # Ensure API call is successful
    assert response.status_code == 200, (
        f"API request failed for principal ID={principal_id}. "
        f"Status: {response.status_code}, Response: {response.text}"
    )

    # Extract response data
    data = response.json().get("data", [])

    # **Fail the test** if no identities were returned (since we expect exactly one)
    assert data, f"Test failed: Expected one identity with principal ID '{principal_id}', but API returned no data."

    # **Ensure only one identity is returned**
    assert len(data) == 1, (
        f"Test failed: Expected exactly one identity with principal ID '{principal_id}', "
        f"but API returned {len(data)} identities.\nReturned records: {data}"
    )
    # Verify the returned identity matches the requested principal ID
    returned_identity = data[0]
    assert returned_identity.get("PRINCIPAL_ID") == principal_id, (
        f"Test failed: Expected identity with PRINCIPAL_ID='{principal_id}', "
        f"but got '{returned_identity.get('PRINCIPAL_ID')}'."
    )

    # Log success
    logger.info(
        f"Test passed: Successfully retrieved the identity with principal ID '{principal_id}'."
    )


def test_filter_identity_by_tags_returns_identities_with_specified_tags(
    identity_v1_client, time_filter, select_identity_tags
):
    """Verify filtering by 'TAGS' returns only identities containing at least one of the specified tags.

    Given:
        - A randomly selected set of tags from an identity in 'list_all_identity'.
        - The API client for identity queries.
        - A valid time filter for the query.

    When:
        - Filtering the API response by 'TAGS'.

    Then:
        - Ensure the API returns **status code 200**.
        - Ensure at least one identity is returned, as the tags exist.
        - Verify that **each returned identity contains at least one of the requested tags**.
        - Log the number of matching identities and their 'PRINCIPAL_ID' values.

    Args:
        identity_v1_client (IdentityV1): API client for querying identities.
        time_filter (dict): Start and end time range for the query.
        select_identity_tags (dict | None): The selected tags for filtering.
    """
    if not select_identity_tags:
        pytest.skip("Skipping test as no identities with tags are found.")

    # Construct API filter for tags (OR condition)
    tag_filters = [
        {"value": f"{key}->{value}", "filterGroup": "include"}
        for key, value in select_identity_tags.items()
    ]

    payload = {
        "ParamInfo": {
            "StartTimeRange": time_filter["StartTimeRange"],
            "EndTimeRange": time_filter["EndTimeRange"],
        },
        "Filters": {
            "CIEM_Identities_Filter.TAGS": tag_filters
        }
    }

    logger.info(f"Testing identity filter with tags: {select_identity_tags}")

    # Make API call
    response = identity_v1_client.query_identities(
        start_time_range=payload["ParamInfo"]["StartTimeRange"],
        end_time_range=payload["ParamInfo"]["EndTimeRange"],
        filters=payload["Filters"]
    )

    # Ensure API call is successful
    assert response.status_code == 200, (
        f"API request failed for TAGS={select_identity_tags}. "
        f"Status: {response.status_code}, Response: {response.text}"
    )

    # Extract response data
    data = response.json().get("data", [])

    # **Fail the test** if no identities were returned (since we expect data)
    assert data, (
        f"Test failed: Expected identities with at least one of the tags {select_identity_tags}, but API returned no data."
    )

    # Verify that each returned identity contains at least one of the requested tags
    mismatched_identities = [
        identity for identity in data if not any(
            key in identity.get("TAGS", {}) and identity["TAGS"][key] == value
            for key, value in select_identity_tags.items()
        )
    ]

    assert not mismatched_identities, (
        f"Found identities that do not contain at least one of the expected tags {select_identity_tags}: "
        f"{mismatched_identities}"
    )

    # Log number of returned identities and their PRINCIPAL_IDs for debugging
    principal_ids = [identity.get("PRINCIPAL_ID") for identity in data]
    logger.info(
        f"Test passed: {len(data)} identities returned with at least one matching tag {select_identity_tags}. "
        f"PRINCIPAL_IDs: {principal_ids}"
    )


def test_filter_identity_by_access_key_returns_expected_records(
    identity_v1_client, time_filter, find_up_to_three_access_key_records
):
    """Verify filtering by 'ACCESS_KEYS_ARRAY' returns only identities containing the specified access keys.

    Args:
        identity_v1_client (IdentityV1): The API client for identity queries.
        time_filter (dict): A dictionary containing 'StartTimeRange' and 'EndTimeRange' for API queries.
        find_up_to_three_access_key_records (list[dict] | None): A list of up to three identity records,
            each containing an access key ID and the corresponding principal ID. Returns None if no access keys are found.

    Given:
        - The 'find_up_to_three_access_key_records' fixture retrieves up to three identities with access keys.
        - The API client for identity queries.
        - A valid time filter for the query.

    When:
        - Filtering the API response by 'ACCESS_KEYS_ARRAY'.

    Then:
        - If no records are found with access keys, **skip the test**.
        - Otherwise, ensure the API returns **status code 200**.
        - Verify that **the response contains the same number of records as the requested access keys**.
        - Verify that **each returned identity contains the correct access key and principal ID**.
    """
    if not find_up_to_three_access_key_records:
        pytest.skip(
            "Skipping test as no identity with access keys is available.")

    # Extract access keys and corresponding principal IDs
    access_keys = [
        record["ACCESS_KEY"] for record in find_up_to_three_access_key_records
    ]
    principal_ids = [
        record["PRINCIPAL_ID"] for record in find_up_to_three_access_key_records
    ]

    logger.info(f"Testing with access keys: {access_keys}")
    logger.info(f"Expected principal IDs: {principal_ids}")

    # Construct API filter
    access_key_filters = [
        {"value": access_key, "filterGroup": "include"} for access_key in access_keys
    ]
    filter_payload = {
        "CIEM_Identities_Filter.ACCESS_KEYS_ARRAY": access_key_filters
    }

    # Make API call
    response = identity_v1_client.query_identities(
        start_time_range=time_filter["StartTimeRange"],
        end_time_range=time_filter["EndTimeRange"],
        filters=filter_payload
    )

    # Ensure API call is successful
    assert response.status_code == 200, (
        f"API request failed for ACCESS_KEYS_ARRAY={access_keys}. "
        f"Status: {response.status_code}, Response: {response.text}"
    )

    # Extract response data
    data = response.json().get("data", [])

    # Ensure the response contains the same number of records as expected
    assert len(data) == len(access_keys), (
        f"Test failed: Expected {len(access_keys)} identities, but API returned {len(data)}."
    )

    # Validate that each returned identity contains the correct access key and principal ID
    mismatched_records = [
        identity for identity in data if identity.get("PRINCIPAL_ID") not in principal_ids
    ]
    assert not mismatched_records, (
        f"Test failed: Found identities that do not match the expected principal IDs. "
        f"Mismatched records: {mismatched_records}"
    )

    # Log successful validation
    logger.info(
        f"Test passed: {len(data)} identities matched the expected access keys and principal IDs."
    )


def test_identity_summary_by_urn_returns_identity_summary(
    identity_v1_client, random_identity
):
    """Verify that querying identity summary by URN returns the expected identity summary.

    Given:
        - A randomly selected identity record from 'random_identity'.
        - The API client for identity queries.

    When:
        - Querying the API for identity summary using 'IDENTITY_URN' and 'START_TIME'.

    Then:
        - Ensure the API returns **status code 200**.
        - Verify that **the response contains identity summary data**.
        - Validate that **the returned summary matches the expected identity URN**.
    Args:
        identity_v1_client (IdentityV1): API client instance for querying identities.
        random_identity (dict): A randomly selected identity record containing 'IDENTITY_URN' and 'START_TIME'.
    """
    if random_identity is None:
        pytest.skip(
            "Skipping test as no identities are available for random selection.")

    identity_urn = random_identity.get("IDENTITY_URN")
    start_time = random_identity.get("START_TIME")

    if not identity_urn or not start_time:
        pytest.skip(
            "Skipping test as the selected identity does not have 'IDENTITY_URN' or 'START_TIME'.")

    logger.info(
        f"Testing identity summary retrieval for identity URN: {identity_urn}")

    # Make API call
    response = identity_v1_client.get_identity_summary_by_urn(
        identity_urn=identity_urn, start_time=start_time
    )

    # Ensure API call is successful
    assert response.status_code == 200, (
        f"API request failed for identity URN={identity_urn}. "
        f"Status: {response.status_code}, Response: {response.text}"
    )

    logger.info(f"API Response JSON: {response.json()}")
    # Extract response data
    data = response.json().get("data", [])

    # **Fail the test** if no summary is returned
    assert data, f"Test failed: Expected identity summary for URN '{identity_urn}', but API returned no data."

    # **Ensure the returned identity URN matches the requested one**
    returned_identity_urns = {identity.get(
        "IDENTITY_URN") for identity in data}
    assert identity_urn in returned_identity_urns, (
        f"Test failed: Expected identity summary for URN '{identity_urn}', but found summaries for URNs: {returned_identity_urns}"
    )

    # Log success
    logger.info(
        f"Test passed: Successfully retrieved identity summary for URN '{identity_urn}'."
    )


def test_verify_identity_entitlements_summary_by_urn_return_entitlements_summary(
    identity_v1_client, random_identity_with_entitlements
):
    """Verify that querying identity entitlements summary by URN returns the expected data.

    Given:
        - A randomly selected identity record **with entitlements** from 'random_identity_with_entitlements'.
        - The API client for identity queries.

    When:
        - Calling the API to fetch the entitlements summary using the identity URN and start time.

    Then:
        - Ensure the API returns **status code 200**.
        - Verify that **the response contains data**.
        - Confirm that **the returned entitlements summary contains the requested identity URN**.

    Args:
        identity_v1_client (IdentityV1): API client for identity queries.
        random_identity_with_entitlements (dict): A randomly selected identity record that has entitlements.
    """
    if random_identity_with_entitlements is None:
        pytest.skip(
            "Skipping test as no identities with entitlements are available for random selection.")

    identity_urn = random_identity_with_entitlements.get("IDENTITY_URN")
    start_time = random_identity_with_entitlements.get("START_TIME")

    if not identity_urn or not start_time:
        pytest.skip(
            "Skipping test as the selected identity is missing 'IDENTITY_URN' or 'START_TIME'.")

    logger.info(
        f"Testing identity entitlements summary for identity: {random_identity_with_entitlements}")

    # Make API call
    response = identity_v1_client.get_identity_entitlements_summary_by_urn(
        identity_urn, start_time)

    # Ensure API call is successful
    assert response.status_code == 200, (
        f"API request failed for identity URN={identity_urn}. "
        f"Status: {response.status_code}, Response: {response.text}"
    )

    logger.info(f"API Response: {response.json()}")

    # Extract response data
    data = response.json().get("data", [])

    # **Fail the test** if no entitlements summary is returned
    assert data, f"Test failed: Expected entitlements summary for '{identity_urn}', but API returned no data."

    # Verify that all returned records have the requested identity URN
    mismatched_urns = [record for record in data if record.get(
        "IDENTITY_URN") != identity_urn]

    assert not mismatched_urns, (
        f"Test failed: Found records with incorrect IDENTITY_URN when filtering for '{identity_urn}': {mismatched_urns}"
    )

    # Log success
    logger.info(
        f"Test passed: Successfully retrieved entitlements summary for identity URN '{identity_urn}'."
    )


@pytest.mark.parametrize("unused_entitlement", UNUSED_ENTITLEMENT)
def test_filter_identity_by_unused_entitlement_returns_identity_with_the_specified_unused_entitlement(
    identity_v1_client, unused_entitlement, entitlement_unused_distribution, time_filter
):
    """Verify filtering by 'ENTITLEMENTS_UNUSED_QUARTILE' returns identities with the specified unused entitlement quartile.

    Given:
        - A list of predefined **unused entitlement quartiles** ('UNUSED_ENTITLEMENT').
        - The API client for identity queries.
        - A fixture ('entitlement_unused_distribution') that provides **existing quartiles and their record counts**.
        - A valid time filter for the query.

    When:
        - Filtering the API response using '"CIEM_Identities_Filter.ENTITLEMENTS_UNUSED_QUARTILE"'.

    Then:
        - If the quartile does not exist in 'entitlement_unused_distribution', **skip the test**.
        - Otherwise:
            - Ensure the API returns **status code 200**.
            - Verify that **all returned identities contain the requested quartile** in '"ENTITLEMENTS_UNUSED_QUARTILE"'.
            - If no data is returned, **fail the test**, since records with that quartile exist.

    Args:
        identity_v1_client (IdentityV1): API client for identity queries.
        unused_entitlement (str): Unused entitlement quartile being tested.
        entitlement_unused_distribution (dict): Fixture mapping quartiles to their counts.
        time_filter (dict): Time filter containing 'StartTimeRange' and 'EndTimeRange'.
    """
    # Ensure the quartile exists in the entitlement distribution fixture
    if unused_entitlement not in entitlement_unused_distribution:
        pytest.skip(
            f"Skipping test: No records found for unused entitlement quartile '{unused_entitlement}'.")

    quartile_value = entitlement_unused_distribution[unused_entitlement]["quartile"]

    logger.info(
        f"Testing filtering by unused entitlement : {unused_entitlement} (Quartile Value: {quartile_value})")

    # Construct API filter for ENTITLEMENTS_UNUSED_QUARTILE
    entitlement_filter = {
        "CIEM_Identities_Filter.ENTITLEMENTS_UNUSED_QUARTILE": [
            {"value": quartile_value, "filterGroup": "include"}
        ]
    }

    # Make API call
    response = identity_v1_client.query_identities(
        start_time_range=time_filter["StartTimeRange"],
        end_time_range=time_filter["EndTimeRange"],
        filters=entitlement_filter
    )

    # Ensure API call is successful
    assert response.status_code == 200, (
        f"API request failed for unused entitlement '{unused_entitlement}' (Quartile Value: {quartile_value}). "
        f"Status: {response.status_code}, Response: {response.text}"
    )

    # Extract response data
    data = response.json().get("data", [])

    # **Fail the test** if no identities were returned (since records exist in the fixture)
    assert data, (
        f"Test failed: Expected identities with unused entitlement '{unused_entitlement}' (Quartile Value: {quartile_value}), "
        f"but API returned no data, response text : {response.text}."
    )

    # Verify all returned identities have the expected quartile
    mismatched_identities = [
        identity for identity in data if identity.get("ENTITLEMENTS_UNUSED_QUARTILE") != quartile_value
    ]

    assert not mismatched_identities, (
        f"Test failed: Found records with incorrect ENTITLEMENTS_UNUSED_QUARTILE when filtering for '{unused_entitlement}' "
        f"(Quartile Value: {quartile_value}): {mismatched_identities}"
    )

    # Log success
    logger.info(
        f"Test passed: Successfully retrieved {len(data)} identities with unused entitlement '{unused_entitlement}' "
        f"(Quartile Value: {quartile_value})."
    )


@pytest.mark.parametrize("used_entitlement", USED_ENTITLEMENT)
def test_filter_identity_by_used_entitlement_returns_identity_with_the_specified_used_entitlement(
    identity_v1_client, used_entitlement, entitlement_used_distribution, time_filter
):
    """Verify filtering by 'ENTITLEMENTS_USED_QUARTILE' returns identities with the specified used entitlement quartile.

    Given:
        - A list of predefined **used entitlement quartiles** ('USED_ENTITLEMENT').
        - The API client for identity queries.
        - A fixture ('entitlement_used_distribution') that provides **existing quartiles and their record counts**.
        - A valid time filter for the query.

    When:
        - Filtering the API response using '"CIEM_Identities_Filter.ENTITLEMENTS_USED_QUARTILE"'.

    Then:
        - If the quartile does not exist in 'entitlement_used_distribution', **skip the test**.
        - Otherwise:
            - Ensure the API returns **status code 200**.
            - Verify that **all returned identities contain the requested quartile** in '"ENTITLEMENTS_USED_QUARTILE"'.
            - If no data is returned, **fail the test**, since records with that quartile exist.

    Args:
        identity_v1_client (IdentityV1): API client for identity queries.
        used_entitlement (str): Used entitlement quartile being tested.
        entitlement_used_distribution (dict): Fixture mapping quartiles to their counts.
        time_filter (dict): Time filter containing 'StartTimeRange' and 'EndTimeRange'.
    """
    # Ensure the quartile exists in the entitlement distribution fixture
    if used_entitlement not in entitlement_used_distribution:
        pytest.skip(
            f"Skipping test: No records found for used entitlement '{used_entitlement}'.")

    quartile_value = entitlement_used_distribution[used_entitlement]["quartile"]

    logger.info(
        f"Testing filtering by used entitlement quartile: {used_entitlement} (Quartile Value: {quartile_value})")

    # Construct API filter for ENTITLEMENTS_USED_QUARTILE
    entitlement_filter = {
        "CIEM_Identities_Filter.ENTITLEMENTS_USED_QUARTILE": [
            {"value": quartile_value, "filterGroup": "include"}
        ]
    }

    # Make API call
    response = identity_v1_client.query_identities(
        start_time_range=time_filter["StartTimeRange"],
        end_time_range=time_filter["EndTimeRange"],
        filters=entitlement_filter
    )

    # Ensure API call is successful
    assert response.status_code == 200, (
        f"API request failed for used entitlement '{used_entitlement}' (Quartile Value: {quartile_value}). "
        f"Status: {response.status_code}, Response: {response.text}"
    )

    # Extract response data
    data = response.json().get("data", [])

    # **Fail the test** if no identities were returned (since records exist in the fixture)
    assert data, (
        f"Test failed: Expected identities with used entitlement '{used_entitlement}' (Quartile Value: {quartile_value}), "
        f"but API returned no data, response text : {response.text}."
    )

    # Verify all returned identities have the expected quartile
    mismatched_identities = [
        identity for identity in data if identity.get("ENTITLEMENTS_USED_QUARTILE") != quartile_value
    ]

    assert not mismatched_identities, (
        f"Test failed: Found records with incorrect ENTITLEMENTS_USED_QUARTILE when filtering for '{used_entitlement}' "
        f"(Quartile Value: {quartile_value}): {mismatched_identities}"
    )

    # Log success
    logger.info(
        f"Test passed: Successfully retrieved {len(data)} identities with used entitlement '{used_entitlement}' "
        f"(Quartile Value: {quartile_value})."
    )
