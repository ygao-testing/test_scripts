import pytest
import logging
import random

from fortiqa.libs.lw.apiv1.helpers.agents_helper import AgentsHelper

logger = logging.getLogger(__name__)


@pytest.fixture
def all_agents(api_v1_client):
    """Fixture to return all Agents in the new agent dashboard"""
    response = AgentsHelper(api_v1_client).list_all_agents_in_new_dashboard()
    return response


@pytest.fixture
def random_agent(all_agents):
    """Fixture to return a randome agent inside the dashboard"""
    if not all_agents:
        pytest.skip(reason="There is no agent in the new agent dashboard")
    random_agent = random.choice(all_agents)
    return random_agent
