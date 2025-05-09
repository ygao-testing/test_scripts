import os
import time
import random
import string
import logging
import pytest
import tftest

from datetime import datetime
from fortiqa.tests.e2e.agents.host_versions import all_tf_modules, linux_tf_modules, windows_tf_modules, supported_csps
from fortiqa.libs.aws.ec2 import EC2Helper
from fortiqa.libs.helper.winrm_helper import WinRmHelper
from fortiqa.libs.lw.apiv1.helpers.agents_helper import AgentsHelper
from fortiqa.libs.helper.ssh_helper import SSHHelper
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.host_vulnerabilities_helper import HostVulnerabilitiesHelper
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.new_vulnerability_dashboard_helper import NewVulnerabilityDashboardHelper

logger = logging.getLogger(__name__)
random_id = ''.join(random.choices(string.ascii_letters, k=4))
tf_owner_prefix = f'agent-{random_id.lower()}'  # GCP naming does not allow underscores and capital letters


@pytest.fixture(scope="package")
def terraform_owner(os_version):
    """Fixture to return the tf_owner value"""
    if os_version in windows_tf_modules:
        # For windows hosts, we need to a hostname with length less than 15 characters
        os_version = os_version.split("windows")[-1]
    owner = f"{tf_owner_prefix}-{os_version}"
    return owner.replace("_", "-").replace('.', '')


@pytest.fixture(scope='package')
def agents_tf_root(request) -> str:
    """Fixture returns root folder for lacework provider TF modules."""
    root = os.path.join(request.config.rootdir, '../terraform/agents/')
    logger.debug(f'{root=}')
    return root


@pytest.fixture(scope='package')
def aws_env_variables(aws_account) -> None:
    """Fixture sets and deletes AWS credentials as env variables."""
    os.environ['AWS_ACCESS_KEY_ID'] = aws_account.aws_access_key_id
    os.environ['AWS_SECRET_ACCESS_KEY'] = aws_account.aws_secret_access_key
    yield
    del os.environ['AWS_ACCESS_KEY_ID']
    del os.environ['AWS_SECRET_ACCESS_KEY']


def apply_tf_modules(module_list: list[str], csp_list: list[str], module_root: str) -> dict[str, dict]:
    """Deploys list of terraform modules.

    Args:
        module_list: list of TF module names.
        module_root: root folder where all TF modules are located.

    Returns: dict[str, dict]
    """
    hosts = {}
    for tf_module in module_list:
        tf = None
        hosts[tf_module] = dict()
        for csp in csp_list:
            module_path = os.path.join(module_root, csp, tf_module)
            if os.path.isdir(module_path):
                tf = tftest.TerraformTest(tf_module, os.path.join(module_root, csp))
                try:
                    tf.setup()
                    os_version = tf_module
                    if os_version in windows_tf_modules:
                        os_version = os_version.split("windows")[-1]
                    owner = f"{tf_owner_prefix}-{os_version}"
                    tf.apply(tf_vars={
                        # gcp does not allow underscores and . in owner name
                        'OWNER': owner.replace("_", "-").replace('.', '')
                    })
                except Exception:
                    logger.exception(f'Failed to deploy TF module {tf_module}')
                finally:
                    hosts[tf_module][csp] = {'tf': tf, 'output': tf.output(), 'deployment_time': time.monotonic(), 'deployment_timestamp': datetime.now()}
            else:
                hosts[tf_module][csp] = None
    return hosts


def destroy_tf_modules(tf_modules: dict) -> None:
    """Destroys list of terraform modules.

    Args:
        module_list: list of TF module names.
        module_root: root folder where all TF modules are located.
    """
    for tf_module in tf_modules:
        for csp in tf_modules[tf_module]:
            if tf_modules[tf_module][csp] is not None:
                try:
                    logger.debug(f'Destroying {tf_module=}')
                    os_version = tf_module
                    if os_version in windows_tf_modules:
                        os_version = os_version.split("windows")[-1]
                    owner = f"{tf_owner_prefix}-{os_version}"
                    tf_modules[tf_module][csp]['tf'].destroy(tf_vars={
                        'OWNER': owner.replace("_", "-").replace('.', '')
                    })
                except Exception:
                    logger.exception(f'Failed to destroy TF module {tf_module}')


@pytest.fixture(scope='package')
def linux_agent_hosts(linux_agent_token, agents_tf_root, aws_env_variables):
    """Fixture applies all TF modules for linux agents."""
    hosts = {}
    try:
        os.environ['TF_VAR_AGENT_DOWNLOAD_URL'] = f"https://fortiqa.lacework.net/mgr/v1/download/{linux_agent_token}/install.sh" # noqa
        hosts = apply_tf_modules(linux_tf_modules, supported_csps, agents_tf_root)
        yield hosts
    finally:
        destroy_tf_modules(hosts)
        if 'TF_VAR_AGENT_DOWNLOAD_URL' in os.environ:
            del os.environ['TF_VAR_AGENT_DOWNLOAD_URL']


@pytest.fixture(scope='package')
def windows_agent_hosts(windows_agent_token, agents_tf_root, aws_env_variables):
    """Fixture applies all TF modules for windows agents."""
    os.environ['TF_VAR_AGENT_ACCESS_TOKEN'] = windows_agent_token
    hosts = apply_tf_modules(windows_tf_modules, supported_csps, agents_tf_root)
    # Giving time for cloud-init on Windows hosts to finish
    try:
        for windows_os in hosts:
            if 'aws' in hosts[windows_os]:
                aws_windows_host = hosts[windows_os]['aws']
                tf_output = aws_windows_host.get('tf').output()
                region = tf_output['region']
                instance_id = tf_output['agent_host_instance_id']
                public_ip = tf_output['agent_host_public_ip']
                password = tf_output['Password']
                EC2Helper(region=region).wait_for_status_and_state(instance_id=instance_id)
                try:
                    WinRmHelper(ip=public_ip, password=password).wait_until_cloud_init_finish()
                except Exception as e:
                    logger.exception(f"Failed to use WinRmHelper to get cloud-init log: {e}")
        yield hosts
    finally:
        destroy_tf_modules(hosts)
        del os.environ['TF_VAR_AGENT_ACCESS_TOKEN']


@pytest.fixture(autouse=True, scope='package')
def all_agent_hosts(windows_agent_hosts, linux_agent_hosts):
    """Fixture returns dictionary with all deployed terraform modules for linux and windows agents."""
    all_hosts = {}
    all_hosts.update(windows_agent_hosts)
    all_hosts.update(linux_agent_hosts)
    return all_hosts


@pytest.fixture(scope='package', params=supported_csps)
def csp(request):
    """Fixture returns one of the supported CSPs"""
    return request.param


@pytest.fixture(scope='package', params=all_tf_modules)
def os_version(request):
    """Fixture returns one of the supported OS versions"""
    return request.param


@pytest.fixture(scope='package')
def agent_host(csp, os_version, all_agent_hosts):
    """Fixture returns details of deployed agent host based on CSP and OS version"""
    if (host := all_agent_hosts.get(os_version).get(csp)) is None:
        pytest.skip(f'TF module {csp}/{os_version} was not found among deployed TF resources')
    else:
        return host


@pytest.fixture(scope='package')
def agent_host_tf_output(agent_host):
    """Fixture returns TF output of the agent host"""
    return agent_host.get('tf').output()


@pytest.fixture(scope="function")
def wait_until_agent_is_added(request, api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Fixture to wait until Agent is added to Agent Dashboard"""
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    try:
        AgentsHelper(api_v1_client, deployment_timestamp).wait_until_agent_is_added(agent_host_instance_id, wait_until=deployment_time+timeout)
        return datetime.now()
    except TimeoutError as e:
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
        logger.error(f"TimeoutError found: {e}, mark test cases xfail"
                     f"Agent is not added to the Dashboard"
                     f"Current Time: {datetime.now()}")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{csp}:{os_version} was not added in the Agent Dashboard: {e}", run=True)
        )
        return None


@pytest.fixture(scope="function")
def wait_until_host_is_active(request, api_v1_client, os_version, csp, agent_host, agent_host_tf_output, wait_until_agent_is_added):
    """Fixture to wait until Agent is active in the Agent Dashboard"""
    if not wait_until_agent_is_added:
        logger.error(f"{os_version} is not added in the Agent Dashboard")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} was not added in the Agent Dashboard", run=False)
        )
        return None
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    try:
        AgentsHelper(api_v1_client, deployment_timestamp).wait_until_agent_is_active(agent_host_instance_id, wait_until=deployment_time+timeout)
        return datetime.now()
    except TimeoutError as e:
        logger.error(f"TimeoutError found: {e}, mark test cases xfail"
                     f"Agent is not Active in the Dashboard"
                     f"Current Time: {datetime.now()}")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} was not active in the Agent Dashboard: {e}", run=True)
        )
        return None


@pytest.fixture(scope="function")
def wait_until_agent_is_added_to_the_new_agent_dashboard(request, api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Fixture to wait until Agent is added to the New Agent Dashboard"""
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    try:
        AgentsHelper(api_v1_client, deployment_timestamp).wait_until_agent_is_added_to_new_dashboard(agent_host_instance_id, wait_until=deployment_time+timeout)
        return datetime.now()
    except TimeoutError as e:
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
        logger.error(f"TimeoutError found: {e}, mark test cases xfail"
                     f"Agent is not added to the New Agent Dashboard"
                     f"Current Time: {datetime.now()}")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{csp}:{os_version} was not added in the Agent Dashboard: {e}", run=False)
        )
        return None


@pytest.fixture(scope="function")
def wait_until_host_is_active_in_the_new_agent_dashboard(request, api_v1_client, os_version, csp, agent_host, agent_host_tf_output, wait_until_agent_is_added_to_the_new_agent_dashboard):
    """Fixture to wait until Agent is active in the New Agent Dashboard"""
    if not wait_until_agent_is_added:
        logger.error(f"{os_version} is not added in the New Agent Dashboard")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} was not added in the New Agent Dashboard", run=False)
        )
        return None
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    try:
        AgentsHelper(api_v1_client, deployment_timestamp).wait_until_agent_is_active_in_new_agent_dashboard(agent_host_instance_id, wait_until=deployment_time+timeout)
        return datetime.now()
    except TimeoutError as e:
        logger.error(f"TimeoutError found: {e}, mark test cases xfail"
                     f"Agent is not active in the New Agent Dashboard"
                     f"Current Time: {datetime.now()}")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} was not active in the New Agent Dashboard: {e}", run=True)
        )
        return None


@pytest.fixture(scope="function")
def wait_until_host_has_any_vulnerability(request, csp, api_v1_client, os_version, agent_host, agent_host_tf_output, wait_until_host_is_active):
    """Fixture to wait until host has more than 0 vulnerabilities"""
    if not wait_until_host_is_active:
        logger.error(f"{os_version} is not active in the Agent Dashboard")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} was not active in the Agent Dashboard", run=False)
        )
        return None
    elif os_version in ["opensuse_leap_15.6", "amazonlinux2023", "centos_stream_9", "centos_stream_10", "windows2016", "windows2019"]:
        request.node.add_marker(
            pytest.mark.xfail(reason="https://lacework.atlassian.net/browse/VULN-1084", run=False)
        )
        return None
    elif "alpine" in os_version:
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} is not supported by Vulnerability dashboard", run=False)
        )
        return None
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    try:
        HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vulnerability(agent_host_instance_id, wait_until=deployment_time+timeout)
        return datetime.now()
    except TimeoutError as e:
        logger.error(f"TimeoutError found: {e}, mark test cases xfail"
                     f"Agent has no vulnerability in the old Vuln Dashboard"
                     f"Current Time: {datetime.now()}")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} has 0 vulnerabilities in the old Vulnerability Dashboard: {e}", run=True)
        )
        return None


@pytest.fixture(scope="function")
def wait_until_host_is_added_to_new_vuln_dashboard(request, csp, api_v1_client, os_version, agent_host, agent_host_tf_output, wait_until_host_is_active, terraform_owner):
    """Fixture to wait until host is added to the new Vuln Dashboard"""
    if not wait_until_host_is_active:
        logger.error(f"{os_version} is not active in the Agent Dashboard")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} was not active in the Agent Dashboard", run=False)
        )
        return None
    elif "alpine" in os_version:
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} is not supported by Vulnerability dashboard", run=False)
        )
        return None
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    try:
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).wait_until_host_is_added(agent_host_instance_id, wait_until=deployment_time+timeout)
        return datetime.now()
    except TimeoutError as e:
        logger.error(f"TimeoutError found: {e}, mark test cases xfail"
                     f"Agent is not added to the new Vuln Dashboard"
                     f"Current Time: {datetime.now()}")
        # Debug purpose
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).fetch_host_by_hostname(hostname=terraform_owner)
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} is not added to the new Vulnerability Dashboard: {e}", run=False)
        )
        return None


@pytest.fixture(scope="function")
def wait_until_host_has_any_vulnerability_in_new_dashboard(request, csp, api_v1_client, os_version, agent_host, agent_host_tf_output, wait_until_host_is_added_to_new_vuln_dashboard, terraform_owner):
    """Fixture to wait until host has more than 0 vulnerabilities"""
    if not wait_until_host_is_added_to_new_vuln_dashboard:
        logger.error(f"{os_version} is not added to the new Vuln Dashboard")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} is not added to the new Vuln Dashboard", run=False)
        )
        return None
    timeout = 15000
    deployment_time = agent_host['deployment_time']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    deployment_timestamp = agent_host['deployment_timestamp']
    try:
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vuln_count(agent_host_instance_id, wait_until=deployment_time+timeout)
        return datetime.now()
    except TimeoutError as e:
        logger.error(f"TimeoutError found: {e}, mark test cases xfail"
                     f"Agent has no vulnerability in the new Vuln Dashboard"
                     f"Current Time: {datetime.now()}")
        # Debug purpose
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).fetch_host_by_hostname(hostname=terraform_owner)
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).fetch_host_by_instance_id(instance_id=agent_host_instance_id)
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} has 0 vulnerabilities in the new Vulnerability Dashboard: {e}", run=True)
        )
        return None
