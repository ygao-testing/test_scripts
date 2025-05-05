import logging
import pytest

from datetime import datetime, timedelta
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard
from fortiqa.libs.lw.apiv1.payloads import AgentlessResourceInventoryFilter

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("resource_id", ["123"])
@pytest.mark.parametrize("operator", ["matches", "does not match", "starts with", "ends with", "includes", "excludes"])
def test_agentless_resource_inventory_resource_id(api_v1_client, resource_id, operator):
    """Test case for Agentless cloud accounts inventory filtered by resource id

    Given: A resource id and an operator
    When: Use api/v1/card/query API to execute the query card
    Then: The API response should be 200

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        resource_id: A test resource id
        operator: Operator to search
    """
    query_card_api = QueryCard(api_v1_client)
    current_time = datetime.now()
    seven_days_ago = current_time - timedelta(days=7)
    tomorrow = current_time + timedelta(days=1)
    search_re = ""
    filter_group = "include"
    match operator:
        case "matches":
            search_re = resource_id
        case "does not match":
            search_re = resource_id
            filter_group = "exclude"
        case "starts with":
            search_re = f"{resource_id}*"
        case "ends with":
            search_re = f"*{resource_id}"
        case "includes":
            search_re = f"*{resource_id}*"
        case "excludes":
            search_re = f"*{resource_id}*"
            filter_group = "exclude"
    payload = {
        "ParamInfo": {
            "StartTimeRange": int(seven_days_ago.timestamp()),
            "EndTimeRange": int(tomorrow.timestamp()),
            "EnableEvalDetailsMView": True
        },
        "Filters": {
            AgentlessResourceInventoryFilter.resource_id: [
                {
                    "value": search_re,
                    "filterGroup": filter_group
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_RESOURCE_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_RESOURCE_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("resource_type", ["Host", "Container"])
def test_agentless_resource_inventory_resource_group(api_v1_client, resource_type):
    """Test case for Agentless cloud accounts inventory filtered by resource type

    Given: A resource type
    When: Use api/v1/card/query API to execute the query card
    Then: The API response should be 200

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        resource_type: A test resource type
    """
    query_card_api = QueryCard(api_v1_client)
    current_time = datetime.now()
    seven_days_ago = current_time - timedelta(days=7)
    tomorrow = current_time + timedelta(days=1)
    payload = {
        "ParamInfo": {
            "StartTimeRange": int(seven_days_ago.timestamp()),
            "EndTimeRange": int(tomorrow.timestamp()),
            "EnableEvalDetailsMView": True
        },
        "Filters": {
            AgentlessResourceInventoryFilter.resource_type: [
                {
                    "value": resource_type,
                    "filterGroup": "include"
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_RESOURCE_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_RESOURCE_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("provider", ["AWS", "GCP"])
def test_agentless_resource_inventory_provider(api_v1_client, provider):
    """Test case for Agentless cloud accounts inventory filtered by provider

    Given: A provider
    When: Use api/v1/card/query API to execute the query card
    Then: The API response should be 200

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        provider: A test provider
    """
    query_card_api = QueryCard(api_v1_client)
    current_time = datetime.now()
    seven_days_ago = current_time - timedelta(days=7)
    tomorrow = current_time + timedelta(days=1)
    payload = {
        "ParamInfo": {
            "StartTimeRange": int(seven_days_ago.timestamp()),
            "EndTimeRange": int(tomorrow.timestamp()),
            "EnableEvalDetailsMView": True
        },
        "Filters": {
            AgentlessResourceInventoryFilter.provider: [
                {
                    "value": provider,
                    "filterGroup": "include"
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_RESOURCE_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_RESOURCE_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("scan_status", [
    "Scanned",
    "Not scanned"
])
def test_agentless_resource_inventory_last_scan_status(api_v1_client, scan_status):
    """Test case for Agentless cloud accounts inventory filtered by last scan status

    Given: An last scan status
    When: Use api/v1/card/query API to execute the query card
    Then: The API response should be 200

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        scan_status: Last scan status
    """
    query_card_api = QueryCard(api_v1_client)
    current_time = datetime.now()
    seven_days_ago = current_time - timedelta(days=7)
    tomorrow = current_time + timedelta(days=1)
    payload = {
        "ParamInfo": {
            "StartTimeRange": int(seven_days_ago.timestamp()),
            "EndTimeRange": int(tomorrow.timestamp()),
            "EnableEvalDetailsMView": True
        },
        "Filters": {
            AgentlessResourceInventoryFilter.last_scan_status: [
                {
                    "value": scan_status,
                    "filterGroup": "include"
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_RESOURCE_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_RESOURCE_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("scan_details", [
    "Host terminated",
    "Pending scan",
    "Not supported"
    "Error while scanning"
])
def test_agentless_resource_inventory_last_scan_details(api_v1_client, scan_details):
    """Test case for Agentless cloud accounts inventory filtered by last scan status

    Given: An last scan status
    When: Use api/v1/card/query API to execute the query card
    Then: The API response should be 200

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        scan_details: Scan details
    """
    query_card_api = QueryCard(api_v1_client)
    current_time = datetime.now()
    seven_days_ago = current_time - timedelta(days=7)
    tomorrow = current_time + timedelta(days=1)
    payload = {
        "ParamInfo": {
            "StartTimeRange": int(seven_days_ago.timestamp()),
            "EndTimeRange": int(tomorrow.timestamp()),
            "EnableEvalDetailsMView": True
        },
        "Filters": {
            AgentlessResourceInventoryFilter.last_scan_details: [
                {
                    "value": scan_details,
                    "filterGroup": "include"
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_RESOURCE_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_RESOURCE_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("resource_name", ["123"])
@pytest.mark.parametrize("operator", ["matches", "does not match", "starts with", "ends with", "includes", "excludes"])
def test_agentless_resource_inventory_resource_name(api_v1_client, resource_name, operator):
    """Test case for Agentless cloud accounts inventory filtered by resource name

    Given: A resource name and an operator
    When: Use api/v1/card/query API to execute the query card
    Then: The API response should be 200

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        resource_name: A test resource name
        operator: Operator to search
    """
    query_card_api = QueryCard(api_v1_client)
    current_time = datetime.now()
    seven_days_ago = current_time - timedelta(days=7)
    tomorrow = current_time + timedelta(days=1)
    search_re = ""
    filter_group = "include"
    match operator:
        case "matches":
            search_re = resource_name
        case "does not match":
            search_re = resource_name
            filter_group = "exclude"
        case "starts with":
            search_re = f"{resource_name}*"
        case "ends with":
            search_re = f"*{resource_name}"
        case "includes":
            search_re = f"*{resource_name}*"
        case "excludes":
            search_re = f"*{resource_name}*"
            filter_group = "exclude"
    payload = {
        "ParamInfo": {
            "StartTimeRange": int(seven_days_ago.timestamp()),
            "EndTimeRange": int(tomorrow.timestamp()),
            "EnableEvalDetailsMView": True
        },
        "Filters": {
            AgentlessResourceInventoryFilter.resource_name: [
                {
                    "value": search_re,
                    "filterGroup": filter_group
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_RESOURCE_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_RESOURCE_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("region", [
    "us-west-2",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
@pytest.mark.parametrize("operator", ["matches", "does not match", "starts with", "ends with", "includes", "excludes"])
def test_agentless_resource_inventory_region(api_v1_client, region, operator):
    """Test case for Agentless cloud accounts inventory filtered by region

    Given: A region and an operator
    When: Use api/v1/card/query API to execute the query card
    Then: The API response should be 200

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        resource_name: A test region
        operator: Operator to search
    """
    query_card_api = QueryCard(api_v1_client)
    current_time = datetime.now()
    seven_days_ago = current_time - timedelta(days=7)
    tomorrow = current_time + timedelta(days=1)
    search_re = ""
    filter_group = "include"
    match operator:
        case "matches":
            search_re = region
        case "does not match":
            search_re = region
            filter_group = "exclude"
        case "starts with":
            search_re = f"{region}*"
        case "ends with":
            search_re = f"*{region}"
        case "includes":
            search_re = f"*{region}*"
        case "excludes":
            search_re = f"*{region}*"
            filter_group = "exclude"
    payload = {
        "ParamInfo": {
            "StartTimeRange": int(seven_days_ago.timestamp()),
            "EndTimeRange": int(tomorrow.timestamp()),
            "EnableEvalDetailsMView": True
        },
        "Filters": {
            AgentlessResourceInventoryFilter.region: [
                {
                    "value": search_re,
                    "filterGroup": filter_group
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_RESOURCE_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_RESOURCE_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("account_id", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
@pytest.mark.parametrize("operator", ["matches", "does not match", "starts with", "ends with", "includes", "excludes"])
def test_agentless_resource_inventory_account_id(api_v1_client, account_id, operator):
    """Test case for Agentless cloud accounts inventory filtered by account_id

    Given: An account_id and an operator
    When: Use api/v1/card/query API to execute the query card
    Then: The API response should be 200

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        resource_name: A test account_id
        operator: Operator to search
    """
    query_card_api = QueryCard(api_v1_client)
    current_time = datetime.now()
    seven_days_ago = current_time - timedelta(days=7)
    tomorrow = current_time + timedelta(days=1)
    search_re = ""
    filter_group = "include"
    match operator:
        case "matches":
            search_re = account_id
        case "does not match":
            search_re = account_id
            filter_group = "exclude"
        case "starts with":
            search_re = f"{account_id}*"
        case "ends with":
            search_re = f"*{account_id}"
        case "includes":
            search_re = f"*{account_id}*"
        case "excludes":
            search_re = f"*{account_id}*"
            filter_group = "exclude"
    payload = {
        "ParamInfo": {
            "StartTimeRange": int(seven_days_ago.timestamp()),
            "EndTimeRange": int(tomorrow.timestamp()),
            "EnableEvalDetailsMView": True
        },
        "Filters": {
            AgentlessResourceInventoryFilter.account: [
                {
                    "value": search_re,
                    "filterGroup": filter_group
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_RESOURCE_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_RESOURCE_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("account_alias", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
@pytest.mark.parametrize("operator", ["matches", "does not match", "starts with", "ends with", "includes", "excludes"])
def test_agentless_resource_inventory_account_alias(api_v1_client, account_alias, operator):
    """Test case for Agentless cloud accounts inventory filtered by account_alias

    Given: An account_alias and an operator
    When: Use api/v1/card/query API to execute the query card
    Then: The API response should be 200

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        resource_name: A test account_alias
        operator: Operator to search
    """
    query_card_api = QueryCard(api_v1_client)
    current_time = datetime.now()
    seven_days_ago = current_time - timedelta(days=7)
    tomorrow = current_time + timedelta(days=1)
    search_re = ""
    filter_group = "include"
    match operator:
        case "matches":
            search_re = account_alias
        case "does not match":
            search_re = account_alias
            filter_group = "exclude"
        case "starts with":
            search_re = f"{account_alias}*"
        case "ends with":
            search_re = f"*{account_alias}"
        case "includes":
            search_re = f"*{account_alias}*"
        case "excludes":
            search_re = f"*{account_alias}*"
            filter_group = "exclude"
    payload = {
        "ParamInfo": {
            "StartTimeRange": int(seven_days_ago.timestamp()),
            "EndTimeRange": int(tomorrow.timestamp()),
            "EnableEvalDetailsMView": True
        },
        "Filters": {
            AgentlessResourceInventoryFilter.account_alias: [
                {
                    "value": search_re,
                    "filterGroup": filter_group
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_RESOURCE_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_RESOURCE_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("org_id", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
@pytest.mark.parametrize("operator", ["matches", "does not match", "starts with", "ends with", "includes", "excludes"])
def test_agentless_resource_inventory_org_id(api_v1_client, org_id, operator):
    """Test case for Agentless cloud accounts inventory filtered by org_id

    Given: An org_id and an operator
    When: Use api/v1/card/query API to execute the query card
    Then: The API response should be 200

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        resource_name: A test org_id
        operator: Operator to search
    """
    query_card_api = QueryCard(api_v1_client)
    current_time = datetime.now()
    seven_days_ago = current_time - timedelta(days=7)
    tomorrow = current_time + timedelta(days=1)
    search_re = ""
    filter_group = "include"
    match operator:
        case "matches":
            search_re = org_id
        case "does not match":
            search_re = org_id
            filter_group = "exclude"
        case "starts with":
            search_re = f"{org_id}*"
        case "ends with":
            search_re = f"*{org_id}"
        case "includes":
            search_re = f"*{org_id}*"
        case "excludes":
            search_re = f"*{org_id}*"
            filter_group = "exclude"
    payload = {
        "ParamInfo": {
            "StartTimeRange": int(seven_days_ago.timestamp()),
            "EndTimeRange": int(tomorrow.timestamp()),
            "EnableEvalDetailsMView": True
        },
        "Filters": {
            AgentlessResourceInventoryFilter.org_id: [
                {
                    "value": search_re,
                    "filterGroup": filter_group
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_RESOURCE_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_RESOURCE_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("failure_reason", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
@pytest.mark.parametrize("operator", ["matches", "does not match", "starts with", "ends with", "includes", "excludes"])
def test_agentless_resource_inventory_failure_reason(api_v1_client, failure_reason, operator):
    """Test case for Agentless cloud accounts inventory filtered by failure_reason

    Given: An failure_reason and an operator
    When: Use api/v1/card/query API to execute the query card
    Then: The API response should be 200

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        resource_name: A test failure_reason
        operator: Operator to search
    """
    query_card_api = QueryCard(api_v1_client)
    current_time = datetime.now()
    seven_days_ago = current_time - timedelta(days=7)
    tomorrow = current_time + timedelta(days=1)
    search_re = ""
    filter_group = "include"
    match operator:
        case "matches":
            search_re = failure_reason
        case "does not match":
            search_re = failure_reason
            filter_group = "exclude"
        case "starts with":
            search_re = f"{failure_reason}*"
        case "ends with":
            search_re = f"*{failure_reason}"
        case "includes":
            search_re = f"*{failure_reason}*"
        case "excludes":
            search_re = f"*{failure_reason}*"
            filter_group = "exclude"
    payload = {
        "ParamInfo": {
            "StartTimeRange": int(seven_days_ago.timestamp()),
            "EndTimeRange": int(tomorrow.timestamp()),
            "EnableEvalDetailsMView": True
        },
        "Filters": {
            AgentlessResourceInventoryFilter.failure_reason: [
                {
                    "value": search_re,
                    "filterGroup": filter_group
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_RESOURCE_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_RESOURCE_INVENTORY, err: {query_response.text}"
