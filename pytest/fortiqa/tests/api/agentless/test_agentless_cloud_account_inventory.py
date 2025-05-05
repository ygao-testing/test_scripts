import logging
import pytest

from datetime import datetime, timedelta
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard
from fortiqa.libs.lw.apiv1.payloads import AgentlessCloudAccountInventoryFilter

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("provider", ["AWS", "GCP"])
def test_agentless_cloud_account_inventory_provider(api_v1_client, provider):
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
            AgentlessCloudAccountInventoryFilter.provider: [
                {
                    "value": provider,
                    "filterGroup": "include"
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_CLOUD_ACCOUNTS_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_CLOUD_ACCOUNTS_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("account_id", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
@pytest.mark.parametrize("operator", ["matches", "does not match", "starts with", "ends with", "includes", "excludes"])
def test_agentless_cloud_account_inventory_account_id(api_v1_client, account_id, operator):
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
            AgentlessCloudAccountInventoryFilter.account: [
                {
                    "value": search_re,
                    "filterGroup": filter_group
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_CLOUD_ACCOUNTS_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_CLOUD_ACCOUNTS_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("account_alias", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
@pytest.mark.parametrize("operator", ["matches", "does not match", "starts with", "ends with", "includes", "excludes"])
def test_agentless_cloud_account_inventory_account_alias(api_v1_client, account_alias, operator):
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
            AgentlessCloudAccountInventoryFilter.account_alias: [
                {
                    "value": search_re,
                    "filterGroup": filter_group
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_CLOUD_ACCOUNTS_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_CLOUD_ACCOUNTS_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("org_id", [
    "123",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
@pytest.mark.parametrize("operator", ["matches", "does not match", "starts with", "ends with", "includes", "excludes"])
def test_agentless_cloud_account_inventory_org_id(api_v1_client, org_id, operator):
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
            AgentlessCloudAccountInventoryFilter.org_id: [
                {
                    "value": search_re,
                    "filterGroup": filter_group
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_CLOUD_ACCOUNTS_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_CLOUD_ACCOUNTS_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("region", [
    "us-west-2",
    pytest.param("-123456", marks=pytest.mark.invalid_input_success)
])
@pytest.mark.parametrize("operator", ["matches", "does not match", "starts with", "ends with", "includes", "excludes"])
# @pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/AWLS2-433")
def test_agentless_cloud_account_inventory_region(api_v1_client, region, operator):
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
    logger.info(filter_group)
    # Waiting for https://lacework.atlassian.net/browse/AWLS2-433 being fixed. We need to use filter_group later
    payload = {
        "ParamInfo": {
            "StartTimeRange": int(seven_days_ago.timestamp()),
            "EndTimeRange": int(tomorrow.timestamp()),
            "EnableEvalDetailsMView": True,
            "Regions": search_re
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_CLOUD_ACCOUNTS_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_CLOUD_ACCOUNTS_INVENTORY, err: {query_response.text}"


@pytest.mark.parametrize("integrated", ["true", "false"])
def test_agentless_cloud_account_agentless_integration(api_v1_client, integrated):
    """Test case for Agentless cloud accounts inventory filtered by agentless configuration

    Given: An agentless configuration option
    When: Use api/v1/card/query API to execute the query card
    Then: The API response should be 200

    Args:
        api_v1_client: API V1 client for interacting with the Lacework
        integrated: An agentless configuration option
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
            AgentlessCloudAccountInventoryFilter.agentless_configuration: [
                {
                    "value": integrated,
                    "filterGroup": "include"
                }
            ]
        }
    }
    query_response = query_card_api.exec_query_card(card_name="Agentless_CLOUD_ACCOUNTS_INVENTORY", payload=payload)
    assert query_response.status_code == 200, f"Fail to execute query card Agentless_CLOUD_ACCOUNTS_INVENTORY, err: {query_response.text}"
