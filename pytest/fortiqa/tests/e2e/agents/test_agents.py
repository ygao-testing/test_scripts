import pytest
import logging

from fortiqa.libs.lw.apiv1.helpers.agents_helper import AgentsHelper
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.host_vulnerabilities_helper import HostVulnerabilitiesHelper
from fortiqa.libs.lw.apiv2.helpers.vulnerability_helper import VulnerabilityHelperV2
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.new_vulnerability_dashboard_helper import NewVulnerabilityDashboardHelper
from fortiqa.tests.e2e.agents.host_versions import linux_tf_modules, windows_tf_modules
from fortiqa.libs.helper.ssh_helper import SSHHelper
from fortiqa.libs.helper.winrm_helper import WinRmHelper

logger = logging.getLogger(__name__)


def test_host_is_added(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
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
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    try:
        AgentsHelper(api_v1_client, deployment_timestamp).wait_until_agent_is_added(agent_host_instance_id, wait_until=deployment_time+timeout)
    except Exception as e:
        public_ip = agent_host_tf_output['agent_host_public_ip']
        # Retrieve and log the cloud-init and datacollector logs
        try:
            ssh_helper = SSHHelper(public_ip, 'fcsqa')
            if os_version in linux_tf_modules:
                cloud_init_log = ssh_helper.get_remote_file_content('/var/log/cloud-init-output.log', use_sudo=True)
                logger.error("Cloud Init Log:")
                logger.error(cloud_init_log)

                datacollector_log = ssh_helper.get_remote_file_content('/var/log/lacework/datacollector.log', use_sudo=True)
                logger.error("Datacollector Log:")
                logger.error(datacollector_log)
            elif os_version in windows_tf_modules and csp == "aws":
                # AWS Windows VMs
                password = agent_host_tf_output['Password']
                cloud_init_log = WinRmHelper(ip=public_ip, password=password).get_windows_cloud_init_log()
                logger.error("Cloud Init Log:")
                logger.error(cloud_init_log)
        except Exception as log_e:
            logger.error(f"Failed to retrieve logs: {str(log_e)}")
        raise e


def test_host_is_active(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
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
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    AgentsHelper(api_v1_client, deployment_timestamp).wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)


def test_host_has_vuln_cve_trend(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
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
    HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_cve_trend(agent_host_instance_id, wait_until=deployment_time+timeout)


def test_host_has_vuln_host_summary(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
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
    HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vuln_host_summary(agent_host_instance_id, wait_until=deployment_time+timeout)


def test_host_has_any_vulnerability(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
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
    if os_version in ["opensuse_leap_15.6", "amazonlinux2023", "centos_stream_9", "centos_stream_10", "alpine3.19"]:
        pytest.xfail(reason="These agent versions always fail the test case")
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vulnerability(agent_host_instance_id, wait_until=deployment_time+timeout)


def test_host_has_any_vulnerability_summary_in_new_dashboard(api_v1_client, os_version, csp, agent_host, terraform_owner, agent_host_tf_output):
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
    finally:
        # Debug purpose
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).fetch_host_by_hostname(hostname=terraform_owner)
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).fetch_host_by_instance_id(instance_id=agent_host_instance_id)


def test_host_has_any_vulnerability_in_new_dashboard(api_v1_client, os_version, csp, agent_host, terraform_owner, agent_host_tf_output):
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
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vuln_count(agent_host_instance_id, wait_until=deployment_time+timeout)
    finally:
        # Debug purpose
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).fetch_host_by_hostname(hostname=terraform_owner)
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).fetch_host_by_instance_id(instance_id=agent_host_instance_id)


def test_host_has_any_vulnerability_observations(api_v2_client, os_version, csp, agent_host, agent_host_tf_output):
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


def test_agent_has_outbound_connection_to_bad_url_alert(api_v1_client, linux_os_version, csp, linux_agent_host):
    """Test agent host has outbound connection to a bad external URL alert.

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      linux_os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      linux_agent_host: tf module deployed for the given os_version and csp.
    """
    if "ubuntu" not in linux_os_version:
        pytest.skip(reason="Only ubuntu hosts installed miners")
    timeout = 15000
    tf_module = linux_agent_host['tf']
    deployment_time = linux_agent_host['deployment_time']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = linux_agent_host['deployment_timestamp']
    agent_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agent_helper.wait_until_agent_dashboard_has_alerts(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)
    alerts = agent_helper.fetch_agent_alerts(filter_type="INSTANCE_ID",
                                             instance_id=agent_host_instance_id)
    found_alert = False
    alert_names = []
    for alert in alerts:
        if alert['alertName'] in ["Outbound connection to a bad external URL", "Connection with a bad external URL"]:
            found_alert = True
        alert_name = alert['alertName']
        alert_names.append(alert_name)
    logger.info(f"Found alerts: {alert_names}")
    assert found_alert, f"Expected to find alert with name Potentially Compromised Host, but found {alert_names}"


def test_agent_has_potentially_compromised_host_alert(api_v1_client, linux_os_version, csp, linux_agent_host):
    """Test agent host has Potentially Compromised Host alert.

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      linux_os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      linux_agent_host: tf module deployed for the given os_version and csp.
    """
    if "ubuntu" not in linux_os_version:
        pytest.skip(reason="Only ubuntu hosts installed miners")
    if "ubuntu2404" == linux_os_version:
        pytest.xfail(reason="https://lacework.atlassian.net/browse/ANEP-3426")
    timeout = 15000
    tf_module = linux_agent_host['tf']
    deployment_time = linux_agent_host['deployment_time']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = linux_agent_host['deployment_timestamp']
    agent_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agent_helper.wait_until_agent_dashboard_has_alerts(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)
    alerts = agent_helper.fetch_agent_alerts(filter_type="INSTANCE_ID",
                                             instance_id=agent_host_instance_id)
    found_alert = False
    alert_names = []
    for alert in alerts:
        if alert['alertName'] == "Potentially Compromised Host":
            found_alert = True
        alert_name = alert['alertName']
        alert_names.append(alert_name)
    logger.info(f"Found alerts: {alert_names}")
    assert found_alert, f"Expected to find alert with name Potentially Compromised Host, but found {alert_names}"


def test_agent_has_malicious_file_alert(api_v1_client, linux_os_version, csp, linux_agent_host):
    """Test agent host has Malicious file alert.

    Given: all agents are deployed
    When: use APIv1 vulnerability query card and filter by instance ID
    Then: assert agent host is returned in API response

    Args:
      api_v1_client: LW API v1 client
      linux_os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      linux_agent_host: tf module deployed for the given os_version and csp.
    """
    if "ubuntu" not in linux_os_version:
        pytest.skip(reason="Only ubuntu hosts installed miners")
    if "ubuntu2404" == linux_os_version:
        pytest.xfail(reason="https://lacework.atlassian.net/browse/ANEP-3426")
    timeout = 15000
    tf_module = linux_agent_host['tf']
    deployment_time = linux_agent_host['deployment_time']
    agent_host_instance_id = tf_module.output()['agent_host_instance_id']
    deployment_timestamp = linux_agent_host['deployment_timestamp']
    agent_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agent_helper.wait_until_agent_dashboard_has_alerts(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)
    alerts = agent_helper.fetch_agent_alerts(filter_type="INSTANCE_ID",
                                             instance_id=agent_host_instance_id)
    found_alert = False
    alert_names = []
    for alert in alerts:
        if alert['alertName'] == "Malicious file":
            found_alert = True
        alert_name = alert['alertName']
        alert_names.append(alert_name)
    logger.info(f"Found alerts: {alert_names}")
    assert found_alert, f"Expected to find alert with name Malicious file, but found {alert_names}"
