import logging
import pytest

from fortiqa.libs.lw.apiv1.helpers.agentless_helper import AgentlessHelper
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.host_vulnerabilities_helper import HostVulnerabilitiesHelper
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.new_vulnerability_dashboard_helper import NewVulnerabilityDashboardHelper
from fortiqa.libs.lw.apiv2.helpers.vulnerability_helper import VulnerabilityHelperV2
from fortiqa.libs.lw.apiv1.api_client.new_vuln.payloads import NewVulnDataclass, QueryEntity, ComparisonOperator
from fortiqa.tests.api.new_vulnerabilities.conftest import generate_new_vuln_payload_and_query
from fortiqa.tests.e2e.agentless.host_versions import all_tf_modules

logger = logging.getLogger(__name__)


def _replace_parameters(params: list, replacements: dict):
    new_params = [
        old_value if old_value not in replacements else replacements[old_value]
        for old_value in params
    ]
    return new_params


def test_host_is_added(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, wait_until_host_is_added):
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
    assert wait_until_host_is_added, f"{os_version} is not added to the Agentless Dashboard"


def test_host_is_scanned(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, wait_until_host_is_scanned):
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
    assert wait_until_host_is_scanned, f"{os_version=} is not scanned by the Agentless scanning"


@pytest.mark.parametrize(
        'os_version',
        _replace_parameters(
            all_tf_modules,
            {
              'windows2016': pytest.mark.skip(reason="Windows Agentless doesn't support container scanning"),
              'windows2019': pytest.mark.skip(reason="Windows Agentless doesn't support container scanning"),
              'windows2022': pytest.mark.skip(reason="Windows Agentless doesn't support container scanning"),
              'alpine3.19': pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/AWLS2-499"),
              'alpine3.20': pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/AWLS2-499"),
              'alpine3.21': pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/AWLS2-499"),
              'amazonlinux2023': pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/AWLS2-499"),
            }
        ),
        indirect=True
)
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
    logger.info(f'test_container_image_added({os_version=})')
    timeout = 18000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    AgentlessHelper(api_v1_client, deployment_timestamp).wait_until_container_image_appear(image_tag=os_version, wait_until=deployment_time+timeout)


@pytest.mark.parametrize(
        'os_version',
        _replace_parameters(
            all_tf_modules,
            {
              'windows2016': pytest.mark.skip(reason="Windows Agentless doesn't support container scanning"),
              'windows2019': pytest.mark.skip(reason="Windows Agentless doesn't support container scanning"),
              'windows2022': pytest.mark.skip(reason="Windows Agentless doesn't support container scanning"),
              'alpine3.19': pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/AWLS2-499"),
              'alpine3.20': pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/AWLS2-499"),
              'alpine3.21': pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/AWLS2-499"),
              'amazonlinux2023': pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/AWLS2-499"),
            }
        ),
        indirect=True
)
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
    logger.info(f'test_container_image_scanned({os_version=})')
    timeout = 18000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    AgentlessHelper(api_v1_client, deployment_timestamp).wait_until_container_images_scanned(image_tag=os_version, wait_until=deployment_time+timeout)


def test_host_has_vuln_cve_trend(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, wait_until_host_is_scanned):
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


def test_host_has_vuln_host_summary(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, wait_until_host_is_scanned):
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


def test_host_has_any_vulnerability(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, wait_until_host_has_any_vulnerability):
    """Test host has more than 0 vulnerabilities.

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
    """
    assert wait_until_host_has_any_vulnerability, f"{os_version} has 0 vulnerability in the old Vuln Dashboard"


def test_host_has_vuln_summary_in_new_vuln_dashboard(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, wait_until_host_is_scanned):
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


def test_host_has_any_vulnerability_in_new_vuln_dashboard(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, wait_until_host_has_any_vulnerability_in_new_vuln_dashboard):
    """Test host has more than 0 vulnerabilities.

    Given: all agents are deployed
    When: use APIv1 vulnerability new dashboard API to query hosts and filter by instance ID
    Then: assert host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
    """
    assert wait_until_host_has_any_vulnerability_in_new_vuln_dashboard, f"{os_version} has 0 vulnerability in the New Vuln Dashboard"


def test_host_has_any_vulnerability_observations(api_v2_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, wait_until_host_has_any_vulnerability):
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


def test_host_has_specific_cve(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, java_cve_packages, wait_until_host_has_any_vulnerability):
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
    tf_module = agent_host['tf']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    host_vuln_helper = HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp)
    hostname = AgentlessHelper(api_v1_client, deployment_timestamp).return_host_name_according_to_instance_id(instance_id=agent_host_instance_id)
    error_messages = []
    for cve_id in java_cve_packages['vulnerabilities']:
        hosts_with_cve = host_vuln_helper.fetch_host_associate_to_cve(cve_id=cve_id)
        if not any(hostname in host.get('HOSTNAME', '') for host in hosts_with_cve):
            error_messages.append(f"Not found {agent_host_instance_id} in hosts associate with {cve_id}")
    assert not error_messages, error_messages


def test_host_has_specific_cve_in_new_vuln_dashboard(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, java_cve_packages, wait_until_host_has_any_vulnerability_in_new_vuln_dashboard):
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
    tf_module = agent_host['tf']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    new_vuln_helper = NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp)
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


@pytest.mark.parametrize("filter", [
    "instance_id",
    "owner",
    "external_ip",
    "internal_ip",
    "hostname"
])
def test_show_vuln_return_cve_in_new_vuln_dashboard(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, java_cve_packages, wait_until_host_has_any_vulnerability_in_new_vuln_dashboard, filter, terraform_owner):
    """Test expected CVE returned by the new Vuln Dashboard by filtering using unique info of the host

    Given: all agents are deployed
    When: use APIv1 vulnerability new dashboard API to query CVEs using info of the host
    Then: assert CVE is returned in API response

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
      cve_id: Vulnerability ID
      filter: Filter used to query New Vuln API
    """
    tf_module = agent_host['tf']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    agentless_helper = AgentlessHelper(api_v1_client, deployment_timestamp)
    error_messages = []
    query_object = NewVulnDataclass(type=QueryEntity.CVES)
    for cve_id in java_cve_packages['vulnerabilities']:
        match filter:
            case "instance_id":
                query_object.add_filter(type="HostFilter",
                                        key="MACHINE_TAGS",
                                        value={"tag_name": "InstanceId", "tag_value": agent_host_instance_id},
                                        operator=ComparisonOperator.IS_EQUAL_TO)
            case "external_ip":
                query_object.add_filter(type="HostFilter",
                                        key="EXTERNAL_IP",
                                        value=agent_host_tf_output['agent_host_public_ip'],
                                        operator=ComparisonOperator.IS_ANY_OF)
            case "internal_ip":
                query_object.add_filter(type="HostFilter",
                                        key="INTERNAL_IP",
                                        value=agent_host_tf_output['agent_host_private_ip'],
                                        operator=ComparisonOperator.IS_ANY_OF)
            case "owner":
                query_object.add_filter(type="HostFilter",
                                        key="MACHINE_TAGS",
                                        value={"tag_name": "Owner", "tag_value": terraform_owner},
                                        operator=ComparisonOperator.IS_EQUAL_TO)
            case "hostname":
                query_object.add_filter(type="HostFilter",
                                        key="HOST_NAME",
                                        value=agentless_helper.return_host_name_according_to_instance_id(instance_id=agent_host_instance_id),
                                        operator=ComparisonOperator.STARTS_WITH)
        query_object.add_filter(type="VulnFilter",
                                key="VULN_ID",
                                value=cve_id,
                                operator=ComparisonOperator.IS_ANY_OF)
        response = generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                                       query_object=query_object,
                                                       query_type="vulnerability",
                                                       host_deployment_timestap=deployment_timestamp)['data']
        found = False
        cve_found = []
        for cve_info in response:
            cve_found.append(cve_info.get('VULN_ID', ''))
            if cve_id == cve_info.get('VULN_ID', ''):
                found = True
                break
        if not found:
            error_messages.append(f"Not found {cve_id=} by using {filter} for {agent_host_instance_id} in the new Vulnerability Dashboard, cve_found: {cve_found}")
    assert not error_messages, error_messages


def test_host_has_specific_package_in_new_vuln_dashboard(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, java_cve_packages, wait_until_host_has_any_vulnerability_in_new_vuln_dashboard):
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
    tf_module = agent_host['tf']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    new_vuln_helper = NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp)
    hostname = AgentlessHelper(api_v1_client, deployment_timestamp).return_host_name_according_to_instance_id(instance_id=agent_host_instance_id)
    hosts_with_cve = new_vuln_helper.fetch_hosts_with_package_found(package_name=java_cve_packages['package_name'])
    found = False
    for host_info in hosts_with_cve:
        if hostname in host_info.get('HOST_NAME', '') and host_info.get('MACHINE_TAGS', {}).get('InstanceId') == agent_host_instance_id:
            found = True
            break
    assert found, f"Not found {hostname=}{agent_host_instance_id=} in hosts with {java_cve_packages['package_name']} downloaded in the new Vulnerability Dashboard"


@pytest.mark.parametrize("filter", [
    "instance_id",
    "owner",
    "external_ip",
    "internal_ip",
    "hostname"
])
def test_show_packages_return_package_in_new_vuln_dashboard(api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, java_cve_packages, wait_until_host_has_any_vulnerability_in_new_vuln_dashboard, filter, terraform_owner):
    """Test Show Packages filtered by host instance_id returns expected package name

    Given: all agents are deployed
    When: use APIv1 vulnerability new dashboard API to query packages filtered by instance id
    Then: assert host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed host terraform modules
      package_name: Package name, it may be a substring of an entire package, e.g. log4j of org.apache.logging.log4j
      filter: Filter used to query New Vuln API
    """
    tf_module = agent_host['tf']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    agentless_helper = AgentlessHelper(api_v1_client, deployment_timestamp)
    query_object = NewVulnDataclass(type=QueryEntity.PACKAGES)
    match filter:
        case "instance_id":
            query_object.add_filter(type="HostFilter",
                                    key="MACHINE_TAGS",
                                    value={"tag_name": "InstanceId", "tag_value": agent_host_instance_id},
                                    operator=ComparisonOperator.IS_EQUAL_TO)
        case "external_ip":
            query_object.add_filter(type="HostFilter",
                                    key="EXTERNAL_IP",
                                    value=agent_host_tf_output['agent_host_public_ip'],
                                    operator=ComparisonOperator.IS_ANY_OF)
        case "internal_ip":
            query_object.add_filter(type="HostFilter",
                                    key="INTERNAL_IP",
                                    value=agent_host_tf_output['agent_host_private_ip'],
                                    operator=ComparisonOperator.IS_ANY_OF)
        case "owner":
            query_object.add_filter(type="HostFilter",
                                    key="MACHINE_TAGS",
                                    value={"tag_name": "Owner", "tag_value": terraform_owner},
                                    operator=ComparisonOperator.IS_EQUAL_TO)
        case "hostname":
            query_object.add_filter(type="HostFilter",
                                    key="HOST_NAME",
                                    value=agentless_helper.return_host_name_according_to_instance_id(instance_id=agent_host_instance_id),
                                    operator=ComparisonOperator.STARTS_WITH)
    response = generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                                   query_object=query_object,
                                                   query_type="package",
                                                   host_deployment_timestap=deployment_timestamp)['data']
    found = False
    package_name = java_cve_packages['package_name']
    for package_info in response:
        if package_name in package_info.get('PACKAGE_NAME', ''):
            found = True
            break
    assert found, f"Not found {package_name=} for packages associated with {agent_host_instance_id=} using {filter=}, {response=}"


@pytest.mark.parametrize("filter", [
    "instance_id",
    "external_ip",
    "internal_ip",
    "hostname",
    "owner"
])
def test_new_vuln_dashboard(api_v1_client, os_version, on_board_agentless_aws_account, agent_host, agent_host_tf_output, wait_until_host_is_added_to_new_vuln_dashboard, filter, terraform_owner):
    """Test case for new Vulnerability Dashboard using deployed hosts

    Given: all agents are deployed
    When: use APIv1 new vulnerability query card and filter by different filters
    Then: assert agent host is returned in API response, and check if returned fields are correct

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
      filter: Filter used to query the New Vuln Dashboard
      terraform_owner: Hostname
    """
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    deployment_timestamp = agent_host['deployment_timestamp']
    agentless_helper = AgentlessHelper(api_v1_client, deployment_timestamp)
    match filter:
        case "instance_id":
            query_object.add_filter(type="HostFilter",
                                    key="MACHINE_TAGS",
                                    value={"tag_name": "InstanceId", "tag_value": agent_host_instance_id},
                                    operator=ComparisonOperator.IS_EQUAL_TO)
        case "external_ip":
            query_object.add_filter(type="HostFilter",
                                    key="EXTERNAL_IP",
                                    value=agent_host_tf_output['agent_host_public_ip'],
                                    operator=ComparisonOperator.IS_ANY_OF)
        case "internal_ip":
            query_object.add_filter(type="HostFilter",
                                    key="INTERNAL_IP",
                                    value=agent_host_tf_output['agent_host_private_ip'],
                                    operator=ComparisonOperator.IS_ANY_OF)
        case "hostname":
            query_object.add_filter(type="HostFilter",
                                    key="HOST_NAME",
                                    value=agentless_helper.return_host_name_according_to_instance_id(instance_id=agent_host_instance_id),
                                    operator=ComparisonOperator.STARTS_WITH)
        case "owner":
            query_object.add_filter(type="HostFilter",
                                    key="MACHINE_TAGS",
                                    value={"tag_name": "Owner", "tag_value": terraform_owner},
                                    operator=ComparisonOperator.IS_EQUAL_TO)
    response = generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                                   query_object=query_object,
                                                   query_type="host",
                                                   host_deployment_timestap=deployment_timestamp)['data']
    assert response, f"Not found {os_version} using {filter} in the new Vuln Dashboard, {response=}"
