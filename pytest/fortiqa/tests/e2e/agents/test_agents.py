import pytest
import logging

from fortiqa.libs.lw.apiv1.helpers.agents_helper import AgentsHelper
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.host_vulnerabilities_helper import HostVulnerabilitiesHelper
from fortiqa.libs.lw.apiv2.helpers.vulnerability_helper import VulnerabilityHelperV2
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.new_vulnerability_dashboard_helper import NewVulnerabilityDashboardHelper
from fortiqa.libs.lw.apiv1.api_client.new_vuln.payloads import NewVulnDataclass, QueryEntity, ComparisonOperator
from fortiqa.tests.api.new_vulnerabilities.conftest import generate_new_vuln_payload_and_query

logger = logging.getLogger(__name__)


def test_host_is_added(api_v1_client, os_version, csp, agent_host, agent_host_tf_output, wait_until_agent_is_added):
    """Test agent is returned by LW API v1.

    Given: all agents are deployed
    When: getting list of available agents using APIv1 query cards
    Then: agent is found in the APIv1 response.

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    logger.info(f'test_agent_is_added({os_version=})')
    assert wait_until_agent_is_added, f"{os_version} is not added to the Agent Dashboard"


def test_host_is_active(api_v1_client, os_version, csp, agent_host, agent_host_tf_output, wait_until_host_is_active):
    """Test agent is active.

    Given: all agents are deployed
    When: getting list of available agents using APIv1 query cards
    Then: assert agent is active.

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    logger.info(f'test_agent_is_active({os_version=})')
    assert wait_until_host_is_active, f"{os_version} is not active in the Agent Dashboard"


def test_host_has_vuln_cve_trend(api_v1_client, os_version, csp, agent_host, agent_host_tf_output, wait_until_host_is_active):
    """Test agent is returned by old vulnerability dashboard query card.

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    if os_version in ["opensuse_leap_15.6", "amazonlinux2023", "centos_stream_9", "centos_stream_10", "alpine3.19"]:
        pytest.xfail(reason="These agent versions always fail the test case")
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    try:
        HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_cve_trend(agent_host_instance_id, wait_until=deployment_time+timeout)
    except TimeoutError:
        if os_version in ["rhel8.9", "ubuntu1604", "ubuntu1804", "rocky8.9", "centos_stream_8", "sles12.sp5", "debian10"]:
            pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/VULN-1083")
        else:
            raise


def test_host_has_vuln_host_summary(api_v1_client, os_version, csp, agent_host, agent_host_tf_output, wait_until_host_is_active):
    """Test agent is returned by old vulnerability dashboard query card.

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    if os_version in ["alpine3.19"]:
        pytest.xfail(reason="These agent versions always fail the test case")
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    try:
        HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vuln_host_summary(agent_host_instance_id, wait_until=deployment_time+timeout)
    except TimeoutError:
        if os_version in ["rhel8.9", "ubuntu1604", "ubuntu1804", "rocky8.9", "centos_stream_8", "sles12.sp5", "debian10"]:
            pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/VULN-1083")
        else:
            raise


def test_host_has_any_vulnerability(api_v1_client, os_version, csp, agent_host, agent_host_tf_output, wait_until_host_has_any_vulnerability):
    """Test agent host has more than 0 vulnerabilities.

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    assert wait_until_host_has_any_vulnerability, f"{os_version} has no vulnerability in the Old Vuln Dashboard"


def test_host_has_any_vulnerability_summary_in_new_dashboard(api_v1_client, os_version, csp, agent_host, terraform_owner, agent_host_tf_output, wait_until_host_is_active):
    """Test agent host has more than 0 vulnerabilities.

    Given: all agents are deployed
    When: use APIv1 vulnerability new dashboard API to query hosts and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    try:
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vuln_summary(agent_host_instance_id, wait_until=deployment_time+timeout)
    except TimeoutError:
        if os_version in ["rhel8.9", "ubuntu1604", "ubuntu1804", "rocky8.9", "centos_stream_8", "sles12.sp5", "debian10"]:
            pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/VULN-1083")
        else:
            raise
    finally:
        # Debug purpose
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).fetch_host_by_hostname(hostname=terraform_owner)
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).fetch_host_by_instance_id(instance_id=agent_host_instance_id)


def test_host_has_any_vulnerability_in_new_dashboard(api_v1_client, os_version, csp, agent_host, terraform_owner, agent_host_tf_output, wait_until_host_has_any_vulnerability_in_new_dashboard):
    """Test agent host has more than 0 vulnerabilities.

    Given: all agents are deployed
    When: use APIv1 vulnerability new dashboard API to query hosts and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    assert wait_until_host_has_any_vulnerability_in_new_dashboard, f"{os_version} has no vulnerability in the New Vuln Dashboard"


def test_host_has_any_vulnerability_observations(api_v2_client, os_version, csp, agent_host, agent_host_tf_output, wait_until_host_has_any_vulnerability):
    """Test host has more than 0 vulnerability observations.

    Given: all agents are deployed
    When: use APIv2 vulnerability obsercation API and filter by instance ID
    Then: assert host is returned in API response

    Args:
      api_v2_client: LW API v2 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    VulnerabilityHelperV2(api_v2_client).wait_until_instance_has_vulnerability_observations(agent_host_instance_id, wait_until=deployment_time+timeout)


def test_agent_has_outbound_connection_to_bad_url_alert(api_v1_client, os_version, csp, agent_host, agent_host_tf_output, wait_until_host_is_active, terraform_owner):
    """Test agent host has outbound connection to a bad external URL alert.

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    if "ubuntu" not in os_version:
        pytest.skip(reason="Only ubuntu hosts installed miners")
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agent_helper.wait_until_agent_dashboard_has_alerts(hostname=terraform_owner, wait_until=deployment_time+timeout)
    alerts = agent_helper.fetch_agent_alerts(filter_type="HOSTNAME",
                                             hostname=terraform_owner)
    found_alert = False
    alert_names = []
    for alert in alerts:
        if alert['alertName'] in ["Outbound connection to a bad external URL", "Connection with a bad external URL"]:
            found_alert = True
        alert_name = alert['alertName']
        alert_names.append(alert_name)
    logger.info(f"Found alerts: {alert_names}")
    if not found_alert:
        pytest.xfail(reason="https://lacework.atlassian.net/browse/FORTIQA-471")
    assert found_alert, f"Expected to find alert with name Potentially Compromised Host, but found {alert_names}"


def test_agent_has_potentially_compromised_host_alert(api_v1_client, os_version, csp, agent_host, agent_host_tf_output, wait_until_host_is_active, terraform_owner):
    """Test agent host has Potentially Compromised Host alert.

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    if "ubuntu" not in os_version:
        pytest.skip(reason="Only ubuntu hosts installed miners")
    if "ubuntu2404" == os_version:
        pytest.xfail(reason="https://lacework.atlassian.net/browse/ANEP-3426")
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agent_helper.wait_until_agent_dashboard_has_alerts(hostname=terraform_owner, wait_until=deployment_time+timeout)
    alerts = agent_helper.fetch_agent_alerts(filter_type="HOSTNAME",
                                             hostname=terraform_owner)
    found_alert = False
    alert_names = []
    for alert in alerts:
        if alert['alertName'] == "Potentially Compromised Host":
            found_alert = True
        alert_name = alert['alertName']
        alert_names.append(alert_name)
    logger.info(f"Found alerts: {alert_names}")
    if not found_alert:
        pytest.xfail(reason="https://lacework.atlassian.net/browse/FORTIQA-471")
    assert found_alert, f"Expected to find alert with name Potentially Compromised Host, but found {alert_names}"


def test_agent_has_malicious_file_alert(api_v1_client, os_version, csp, agent_host, agent_host_tf_output, wait_until_host_is_active, terraform_owner):
    """Test agent host has Malicious file alert.

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    if "ubuntu" not in os_version:
        pytest.skip(reason="Only ubuntu hosts installed miners")
    if "ubuntu2404" == os_version:
        pytest.xfail(reason="https://lacework.atlassian.net/browse/ANEP-3426")
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agent_helper.wait_until_agent_dashboard_has_alerts(hostname=terraform_owner, wait_until=deployment_time+timeout)
    alerts = agent_helper.fetch_agent_alerts(filter_type="HOSTNAME",
                                             hostname=terraform_owner)
    found_alert = False
    alert_names = []
    for alert in alerts:
        if alert['alertName'] == "Malicious file":
            found_alert = True
        alert_name = alert['alertName']
        alert_names.append(alert_name)
    logger.info(f"Found alerts: {alert_names}")
    assert found_alert, f"Expected to find alert with name Malicious file, but found {alert_names}"


@pytest.mark.parametrize("filter", [
    "hostname",
    "instance_id",
    "mid",
    "external_ip",
    "internal_ip"
])
def test_new_vuln_dashboard(api_v1_client, os_version, csp, agent_host, agent_host_tf_output, wait_until_host_is_added_to_new_vuln_dashboard, filter, terraform_owner):
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
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    query_object = NewVulnDataclass(type=QueryEntity.HOSTS)
    match filter:
        case "hostname":
            query_object.add_filter(type="HostFilter",
                                    key="HOST_NAME",
                                    value=terraform_owner,
                                    operator=ComparisonOperator.IS_EQUAL_TO)
        case "instance_id":
            query_object.add_filter(type="HostFilter",
                                    key="MACHINE_TAGS",
                                    value={"tag_name": "InstanceId", "tag_value": agent_host_instance_id},
                                    operator=ComparisonOperator.IS_EQUAL_TO)
        case "mid":
            query_object.add_filter(type="HostFilter",
                                    key="MACHINE_ID",
                                    value=agent_helper.fetch_host_MID_by_hostname(terraform_owner),
                                    operator=ComparisonOperator.IS_EQUAL_TO)
        case "external_ip":
            query_object.add_filter(type="HostFilter",
                                    key="EXTERNAL_IP",
                                    value=agent_host_tf_output['agent_host_public_ip'],
                                    operator=ComparisonOperator.IS_ANY_OF)
            query_object.add_filter(type="HostFilter",
                                    key="MACHINE_TAGS",
                                    value={"tag_name": "InstanceId", "tag_value": agent_host_instance_id},
                                    operator=ComparisonOperator.IS_EQUAL_TO)
        case "internal_ip":
            query_object.add_filter(type="HostFilter",
                                    key="INTERNAL_IP",
                                    value=agent_host_tf_output['agent_host_private_ip'],
                                    operator=ComparisonOperator.IS_ANY_OF)
            query_object.add_filter(type="HostFilter",
                                    key="MACHINE_TAGS",
                                    value={"tag_name": "InstanceId", "tag_value": agent_host_instance_id},
                                    operator=ComparisonOperator.IS_EQUAL_TO)
    response = generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                                   query_object=query_object,
                                                   query_type="host",
                                                   host_deployment_timestap=deployment_timestamp)['data']
    if not response and filter in ['mid', 'external_ip']:
        pytest.xfail(reason="https://lacework.atlassian.net/browse/VULN-1098")
    elif not response:
        query_object.add_filter(type="HostFilter",
                                key="MACHINE_ID",
                                value=agent_helper.fetch_host_MID_by_hostname(terraform_owner),
                                operator=ComparisonOperator.IS_EQUAL_TO)
        response_by_mid = generate_new_vuln_payload_and_query(api_v1_client=api_v1_client,
                                                              query_object=query_object,
                                                              query_type="host",
                                                              host_deployment_timestap=deployment_timestamp)['data']
        logger.debug(f"Response from filtering by MID: {response_by_mid}")
        if response_by_mid and filter == "hostname":
            pytest.xfail(reason="https://lacework.atlassian.net/browse/VULN-1111")
    assert response, f"Not found {os_version} using {filter} in the new Vuln Dashboard, {response=}"
