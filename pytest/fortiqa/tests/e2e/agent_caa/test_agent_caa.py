import logging
import pytest

from fortiqa.libs.lw.apiv1.helpers.agentless_helper import AgentlessHelper
from fortiqa.libs.lw.apiv1.helpers.agents_helper import AgentsHelper
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.host_vulnerabilities_helper import HostVulnerabilitiesHelper
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.new_vulnerability_dashboard_helper import NewVulnerabilityDashboardHelper

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("package_name", ["org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j:log4j-api"])
def test_caa_agent(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, package_name):
    """Test Code Aware Agent

    Given: all host are deployed, agentless_scanning onboarded and agent installed
    When: getting list of active packages
    Then: expected package is found and active

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version to test
      agent_host: Deployed VM
      on_board_agentless_aws_account: Onboarded agentless scanning account
    """
    if os_version == "alpine3.19":
        pytest.xfail(reason="Alpine is not supported by Vuln Dashboard")
    logger.info(f'test_caa_agent({os_version=})')
    timeout = 30000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    AgentlessHelper(api_v1_client, deployment_timestamp).wait_until_host_appear(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)
    AgentlessHelper(api_v1_client, deployment_timestamp).wait_until_host_scanned(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)
    AgentsHelper(api_v1_client, deployment_timestamp).wait_until_agent_is_added(agent_host_instance_id, wait_until=deployment_time+timeout)
    AgentsHelper(api_v1_client, deployment_timestamp).wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vulnerability(agent_host_instance_id, wait_until=deployment_time+timeout)
    HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_instance_change_to_agent_and_agentless_coverage_type(agent_host_instance_id, wait_until=deployment_time+timeout)
    HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_package_appears_for_host(package_name, agent_host_instance_id, wait_until=deployment_time+timeout)
    HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_package_active_for_host(package_name, agent_host_instance_id, wait_until=deployment_time+timeout)


@pytest.mark.parametrize("package_name", ["org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j:log4j-api"])
def test_caa_agent_new_vuln_dashboard(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, package_name):
    """Test Code Aware Agent

    Given: all host are deployed, agentless_scanning onboarded and agent installed
    When: getting list of active packages
    Then: expected package is found and active

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version to test
      agent_host: Deployed VM
      on_board_agentless_aws_account: Onboarded agentless scanning account
    """
    if os_version == "alpine3.19":
        pytest.xfail(reason="Alpine is not supported by Vuln Dashboard")
    logger.info(f'test_caa_agent({os_version=})')
    timeout = 36000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    AgentlessHelper(api_v1_client, deployment_timestamp).wait_until_host_appear(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)
    AgentlessHelper(api_v1_client, deployment_timestamp).wait_until_host_scanned(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)
    AgentsHelper(api_v1_client, deployment_timestamp).wait_until_agent_is_added(agent_host_instance_id, wait_until=deployment_time+timeout)
    AgentsHelper(api_v1_client, deployment_timestamp).wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vuln_count(agent_host_instance_id, wait_until=deployment_time+timeout)
    NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).wait_until_instance_change_to_agent_and_agentless_coverage_type(agent_host_instance_id, wait_until=deployment_time+timeout)
    NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).wait_until_package_appears_for_host(package_name, agent_host_instance_id, wait_until=deployment_time+timeout)
    NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).wait_until_package_active_for_host(package_name, agent_host_instance_id, wait_until=deployment_time+timeout)
