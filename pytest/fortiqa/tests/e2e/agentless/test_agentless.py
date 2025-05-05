import logging
import pytest

from fortiqa.libs.lw.apiv1.helpers.agentless_helper import AgentlessHelper
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.host_vulnerabilities_helper import HostVulnerabilitiesHelper
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.new_vulnerability_dashboard_helper import NewVulnerabilityDashboardHelper
from fortiqa.libs.lw.apiv2.helpers.vulnerability_helper import VulnerabilityHelperV2

logger = logging.getLogger(__name__)


def test_host_is_added(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account):
    """Test host is returned by LW API v1.

    Given: all host are deployed
    When: getting list of available agents using APIv1 query cards
    Then: host is found in the APIv1 response.

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
    """
    logger.info(f'test_host_is_added({os_version=})')
    timeout = 18000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    AgentlessHelper(api_v1_client, deployment_timestamp).wait_until_host_appear(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_host_is_scanned(api_v1_client, os_version, agent_host, on_board_agentless_aws_account):
    """Test host is scanned.

    Given: all agents are deployed
    When: getting list of available agents using APIv1 query cards
    Then: assert host is scanned.

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
    """
    logger.info(f'test_host_is_scanned({os_version=})')
    timeout = 18000
    tf_module = agent_host['tf']
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    AgentlessHelper(api_v1_client, deployment_timestamp).wait_until_host_scanned(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)


def test_container_image_added(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account):
    """Test container image is returned by LW API v1.

    Given: all host are deployed, and containers are up
    When: getting list of available agents using APIv1 query cards
    Then: container image is found in the APIv1 response.

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
    """
    if "windows" in os_version:
        pytest.xfail(reason="Windows hosts do not include container")
    logger.info(f'test_container_image_added({os_version=})')
    timeout = 18000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    AgentlessHelper(api_v1_client, deployment_timestamp).wait_until_container_image_appear(image_tag=os_version, wait_until=deployment_time+timeout)


def test_container_image_scanned(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account):
    """Test container image is scanned.

    Given: all host are deployed, and containers are up
    When: getting list of available agents using APIv1 query cards
    Then: container image is scanned in the APIv1 response.

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
    """
    if "windows" in os_version:
        pytest.xfail(reason="Windows hosts do not include container")
    logger.info(f'test_container_image_scanned({os_version=})')
    timeout = 18000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    AgentlessHelper(api_v1_client, deployment_timestamp).wait_until_container_images_scanned(image_tag=os_version, wait_until=deployment_time+timeout)


def test_host_has_vuln_cve_trend(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account):
    """Test agent is returned by old vulnerability dashboard query card.

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed agent terraform modules
    """
    timeout = 18000
    tf_module = agent_host['tf']
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_cve_trend(agent_host_instance_id, wait_until=deployment_time+timeout)


def test_host_has_vuln_host_summary(api_v1_client, os_version, agent_host, on_board_agentless_aws_account):
    """Test agent is returned by old vulnerability dashboard query card.

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed agent terraform modules
    """
    timeout = 18000
    tf_module = agent_host['tf']
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vuln_host_summary(agent_host_instance_id, wait_until=deployment_time+timeout)


def test_host_has_any_vulnerability(api_v1_client, os_version, agent_host, on_board_agentless_aws_account):
    """Test host has more than 0 vulnerabilities.

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
    """
    timeout = 18000
    tf_module = agent_host['tf']
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vulnerability(agent_host_instance_id, wait_until=deployment_time+timeout)


def test_host_has_vuln_summary_in_new_vuln_dashboard(api_v1_client, os_version, agent_host, on_board_agentless_aws_account):
    """Test agent is returned by old vulnerability dashboard query card.

    Given: all agents are deployed
    When: use APIv1 vulnerability new dashboard API to query hosts and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed agent terraform modules
    """
    timeout = 18000
    tf_module = agent_host['tf']
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vuln_summary(agent_host_instance_id, wait_until=deployment_time+timeout)


def test_host_has_any_vulnerability_in_new_vuln_dashboard(api_v1_client, os_version, agent_host, on_board_agentless_aws_account):
    """Test host has more than 0 vulnerabilities.

    Given: all agents are deployed
    When: use APIv1 vulnerability new dashboard API to query hosts and filter by instance ID
    Then: assert host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
    """
    timeout = 18000
    tf_module = agent_host['tf']
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vuln_count(agent_host_instance_id, wait_until=deployment_time+timeout)


def test_host_has_any_vulnerability_observations(api_v2_client, os_version, agent_host, on_board_agentless_aws_account):
    """Test host has more than 0 vulnerability observations.

    Given: all agents are deployed
    When: use APIv2 vulnerability obsercation API and filter by instance ID
    Then: assert host is returned in API response

    Args:
      api_v2_client: LW API v2 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
    """
    timeout = 18000
    tf_module = agent_host['tf']
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    VulnerabilityHelperV2(api_v2_client).wait_until_instance_has_vulnerability_observations(agent_host_instance_id, wait_until=deployment_time+timeout)


def test_host_has_specific_cve(api_v1_client, os_version, agent_host, on_board_agentless_aws_account, java_cve_packages):
    """Test host has specific CVE scanned

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by hosts associate with specific CVE
    Then: assert host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
      cve_id: Vulnerability ID
    """
    if "alpine" in os_version:
        pytest.xfail(reason="Alpine is not supported by Vuln")
    timeout = 18000
    tf_module = agent_host['tf']
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    host_vuln_helper = HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp)
    host_vuln_helper.wait_until_instance_has_vulnerability(agent_host_instance_id, wait_until=deployment_time+timeout)
    hostname = AgentlessHelper(api_v1_client, deployment_timestamp).return_host_name_according_to_instance_id(instance_id=agent_host_instance_id)
    error_messages = []
    for cve_id in java_cve_packages['vulnerabilities']:
        hosts_with_cve = host_vuln_helper.fetch_host_associate_to_cve(cve_id=cve_id)
        if not any(hostname in host.get('HOSTNAME', '') for host in hosts_with_cve):
            error_messages.append(f"Not found {agent_host_instance_id} in hosts associate with {cve_id}")
    assert not error_messages, error_messages


def test_host_has_specific_cve_in_new_vuln_dashboard(api_v1_client, os_version, agent_host, on_board_agentless_aws_account, java_cve_packages):
    """Test host has specific CVE scanned in new Vulnerability Dashboard

    Given: all agents are deployed
    When: use APIv1 vulnerability new dashboard API to query hosts that associate with specific CVE
    Then: assert host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
      cve_id: Vulnerability ID
    """
    if "alpine" in os_version:
        pytest.xfail(reason="Alpine is not supported by Vuln")
    timeout = 18000
    tf_module = agent_host['tf']
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    new_vuln_helper = NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp)
    new_vuln_helper.wait_until_instance_has_vuln_count(agent_host_instance_id, wait_until=deployment_time+timeout)
    hostname = AgentlessHelper(api_v1_client, deployment_timestamp).return_host_name_according_to_instance_id(instance_id=agent_host_instance_id)
    error_messages = []
    for cve_id in java_cve_packages['vulnerabilities']:
        hosts_with_cve = new_vuln_helper.fetch_hosts_with_cve_id(cve_id=cve_id)
        found = False
        for host_info in hosts_with_cve:
            if hostname in host_info.get('HOST_NAME', '') and host_info.get('MACHINE_TAGS', {}).get('InstanceId') == agent_host_instance_id:
                found = True
                break
        if not found:
            error_messages.append(f"Not found {hostname=}{agent_host_instance_id=} in hosts associate with {cve_id} in the new Vulnerability Dashboard")
    assert not error_messages, error_messages


def test_host_has_specific_package_in_new_vuln_dashboard(api_v1_client, os_version, agent_host, on_board_agentless_aws_account, java_cve_packages):
    """Test host has specific package scanned

    Given: all agents are deployed
    When: use APIv1 vulnerability new dashboard API to query hosts that associate with specific CVE
    Then: assert host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
      package_name: Package name, it may be a substring of an entire package, e.g. log4j of org.apache.logging.log4j
    """
    if "alpine" in os_version:
        pytest.xfail(reason="Alpine is not supported by Vuln")
    timeout = 18000
    tf_module = agent_host['tf']
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    new_vuln_helper = NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp)
    new_vuln_helper.wait_until_instance_has_vuln_count(agent_host_instance_id, wait_until=deployment_time+timeout)
    hostname = AgentlessHelper(api_v1_client, deployment_timestamp).return_host_name_according_to_instance_id(instance_id=agent_host_instance_id)
    hosts_with_cve = new_vuln_helper.fetch_hosts_with_package_found(package_name=java_cve_packages['package_name'])
    found = False
    for host_info in hosts_with_cve:
        if hostname in host_info.get('HOST_NAME', '') and host_info.get('MACHINE_TAGS', {}).get('InstanceId') == agent_host_instance_id:
            found = True
            break
    assert found, f"Not found {hostname=}{agent_host_instance_id=} in hosts with {java_cve_packages['package_name']} downloaded in the new Vulnerability Dashboard"


def test_show_packages_return_package_in_new_vuln_dashboard(api_v1_client, os_version, agent_host, on_board_agentless_aws_account, java_cve_packages):
    """Test Show Packages filtered by host instance_id returns expected package name

    Given: all agents are deployed
    When: use APIv1 vulnerability new dashboard API to query packages filtered by instance id
    Then: assert host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
      package_name: Package name, it may be a substring of an entire package, e.g. log4j of org.apache.logging.log4j
    """
    if "alpine" in os_version:
        pytest.xfail(reason="Alpine is not supported by Vuln")
    timeout = 18000
    tf_module = agent_host['tf']
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    new_vuln_helper = NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp)
    new_vuln_helper.wait_until_instance_has_vuln_count(agent_host_instance_id, wait_until=deployment_time+timeout)
    packages_associated = new_vuln_helper.fetch_packages_associate_with_host_by_instance_id(instance_id=agent_host_instance_id)
    found = False
    package_name = java_cve_packages['package_name']
    for package_info in packages_associated:
        if package_name in package_info.get('PACKAGE_NAME', ''):
            found = True
            break
    assert found, f"Not found {package_name=} for packages associated with {agent_host_instance_id=} in the new Vulnerability Dashboard"
