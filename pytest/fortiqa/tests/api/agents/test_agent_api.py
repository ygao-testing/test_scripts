import logging
import pytest
import json
import random
import itertools
import copy

from fortiqa.libs.lw.apiv1.payloads import AgentFilter
from fortiqa.libs.lw.apiv1.helpers.agents_helper import AgentsHelper
from fortiqa.libs.lw.apiv1.api_client.new_agent_dashboard.new_agent_dashboard import NewAgentDashboard


logger = logging.getLogger(__name__)


filters = AgentFilter.all_filters()
num_elements = random.randint(1, len(filters))
combinations = list(itertools.combinations(filters, num_elements))
random_combination = list(random.choice(combinations))


@pytest.mark.qa_pre_merge
@pytest.mark.parametrize("filters", [random_combination])
def test_new_agent_dashboard_api(api_v1_client, filters, random_agent):
    """Test case for the New Agent Dashboard V1 API

    Given: Random combination of all filters, and a random fetched agent inside the dashboard
    When: Using API V1 with information of that agent
    Then: API response should contain that agent

    Args:
        api_v1_client: API V1 client for interacting with the Lacework.
        filters: A list of filters
        random_agent: A randomly fetched agent
    """
    agent_helper = AgentsHelper(api_v1_client)
    payload = copy.deepcopy(agent_helper.new_dashboard_payload_template)
    for filter in filters:
        match filter:
            case "OS":
                payload['Filters'][AgentFilter.OS] = [{
                    "value": random_agent['OS'],
                    "filterGroup": "include"
                }]
            case "HOSTNAME":
                payload['Filters'][AgentFilter.HOSTNAME] = [{
                    "value": random_agent['HOSTNAME'],
                    "filterGroup": "include"
                }]
            case "IP_ADDRESS":
                payload['Filters'][AgentFilter.IP_ADDRESS] = [{
                    "value": random_agent['IP_ADDRESS'],
                    "filterGroup": "include"
                }]
            case "TOKEN":
                payload['Filters'][AgentFilter.TOKEN] = [{
                    "value": random_agent['TOKEN'],
                    "filterGroup": "include"
                }]
            case "AGENT_VERSION":
                payload['Filters'][AgentFilter.AGENT_VERSION] = [{
                    "value": random_agent['AGENT_VERSION'],
                    "filterGroup": "include"
                }]
            case "STATUS":
                payload['Filters'][AgentFilter.STATUS] = [{
                    "value": random_agent['STATUS'],
                    "filterGroup": "include"
                }]
            case "AUTOUPGRADE":
                payload['Filters'][AgentFilter.AUTOUPGRADE] = [{
                    "value": random_agent['AUTOUPGRADE'],
                    "filterGroup": "include"
                }]
            case "INSTANCE_ID":
                payload['Filters'][AgentFilter.INSTANCE_ID] = [{
                    "value": random_agent.get('MACHINE_TAGS', {}).get('InstanceId'),
                    "filterGroup": "include"
                }]
    logger.info(f"Payload: {json.dumps(payload, indent=2)}")
    response = NewAgentDashboard(api_v1_client).get_agent_inventory(payload=payload)
    assert response.status_code == 200, f"Failed to get the agent inventory, error: {response.text}"
    logger.info(f"Agent dashboard API response: {response.json()}")
    assert random_agent in response.json()['data'], f"Expected to find the random agent {random_agent}, but not found"
