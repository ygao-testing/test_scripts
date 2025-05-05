import pytest
import logging

from fortiqa.libs.lw.apiv1.helpers.agents_helper import AgentsHelper
from fortiqa.tests.e2e.agents.host_versions import windows_tf_modules, linux_tf_modules

logger = logging.getLogger(__name__)


def test_agent_dashboard_unique_machines(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows Unique Machines

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent unique machine query card
    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_unique_machines(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_unique_users(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows Unique Users

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent unique user query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_unique_users(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_total_bytes(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows total bytes

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent total bytes query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_total_bytes(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_total_connections(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows total connections

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent total connections query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_total_connections(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_external_out_bytes(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows external out bytes

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent external out bytes query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_external_out_bytes(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_external_in_bytes(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows external in bytes

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent external in bytes query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_external_in_bytes(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_external_out_connections(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows external out connections

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent external out connections query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_external_out_connections(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_external_in_connections(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows external in connections

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent external in connections query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_external_in_connections(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_instance_id_mapping(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows instance ID mapping

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent instance ID mapping query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_instance_id_mapping(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_tcp_external_server_connection_details(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows tcp external server connection details

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent tcp external server connection details query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_tcp_external_server_connection_details(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_active_executables(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows list of active executables

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent list of active executables query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_list_of_active_executables(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_executables_info(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows executables details

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent executable information query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_executable_info(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_machine_properties(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows machine properties

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent machine properties query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_machine_properties(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_machine_tags(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows machine tags

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent machine tags query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_machine_tag_summary(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_unique_process_details(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows unique process details

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent unique process details query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_unique_process_details(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_exposed_ports(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows exposed ports info

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from exposed ports query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_exposed_ports(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_dashboard_domain_lookups(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows domain lookups info

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from domain lookups query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_domain_lookups(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


@pytest.mark.parametrize('csp', [
        'aws',
        pytest.param('azure', marks=pytest.mark.xfail(reason='https://lacework.atlassian.net/browse/FORTIQA-378')),
        pytest.param('gcp', marks=pytest.mark.xfail(reason='https://lacework.atlassian.net/browse/FORTIQA-378')),
    ], indirect=True)
def test_agent_dashboard_udp_external_client_connection_details(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows udp external client connection details

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from udp external client connection details query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    if os_version not in windows_tf_modules:
        pytest.skip(reason="Only Windows agent has udp_external_client_connection_details data")
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_udp_external_client_connection_details(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


@pytest.mark.skip(reason="Need to discuss with dev team for more details")
def test_agent_dashboard_tcp_internal_connection_to_internal_devices_without_agents(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows TCP-Internal Connection to Internal Devices without Agents details

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from TCP-Internal Connection to Internal Devices without Agents query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_tcp_internal_connection_to_internal_devices_without_agents(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


@pytest.mark.skip(reason="All hosts have no data inside TCP internal connection from internal devices without agents board")
def test_agent_dashboard_tcp_internal_connection_from_internal_devices_without_agents(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows TCP-Internal Connection from Internal Devices without Agents details

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from TCP-Internal Connection from Internal Devices without Agents query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_tcp_internal_connection_from_internal_devices_without_agents(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


@pytest.mark.skip(reason="All hosts have no data inside TCP internal connection from internal devices without agents board")
def test_agent_dashboard_udp_internal_connection_from_internal_devices_without_agents(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows UDP-Internal Connection from Internal Devices without Agents details

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from UDP-Internal Connection from Internal Devices without Agents query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_udp_internal_connection_from_internal_devices_without_agents(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


@pytest.mark.skip(reason="Need to discuss with dev team for more details")
def test_agent_dashboard_udp_internal_connection_to_internal_devices_without_agents(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows UDP-Internal Connection to Internal Devices without Agents details

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from UDP-Internal Connection to Internal Devices without Agents query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_udp_internal_connection_to_internal_devices_without_agents(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


@pytest.mark.parametrize('os_version', set(linux_tf_modules).intersection([
    'alpine3.19',
    'debian10', 'debian11', 'debian12',
    'amazonlinux2', 'amazonlinux2023',
    'ubuntu1604', 'ubuntu1804', 'ubuntu2004', 'ubuntu2204', 'ubuntu2404',
    'rhel8.9', 'rhel9.4',
    'rocky8.9', 'rocky9.4',
    'oraclelinux89', 'oraclelinux93',
    'centos_stream_8', 'centos_stream_9', 'centos_stream_10',
]), indirect=True)
@pytest.mark.parametrize('csp', ['aws'], indirect=True)
def test_agent_dashboard_active_containers(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test agent dashboard shows list of active containers

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert there is data returned from agent list of active executables query card

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
    agents_helper.wait_until_agent_dashboard_has_list_of_active_containers(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)
