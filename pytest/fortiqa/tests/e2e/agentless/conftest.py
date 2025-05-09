import os
import time
import random
import string
import logging

import pytest
import tftest

from datetime import datetime
from fortiqa.libs.lw.apiv2.helpers.agent_token_helper import AgentTokenHelper
from fortiqa.libs.lw.apiv1.api_client.cloud_accounts.integrations import Integrations
from fortiqa.libs.lw.apiv2.api_client.agent_access_tokens.agent_access_tokens import AgentAccessToken
from fortiqa.tests.e2e.agentless.host_versions import all_tf_modules, windows_tf_modules, linux_tf_modules
from fortiqa.tests.e2e.agentless.cve_packages import packages
from fortiqa.tests.e2e.integrations.cloud_accounts.helpers import generate_and_run_aws_agentless_cft
from fortiqa.libs.aws.cloudformation import CloudformationHelper
from fortiqa.libs.aws.ec2 import EC2Helper
from fortiqa.libs.helper.winrm_helper import WinRmHelper
from fortiqa.libs.lw.apiv1.helpers.agentless_helper import AgentlessHelper
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.host_vulnerabilities_helper import HostVulnerabilitiesHelper
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.new_vulnerability_dashboard_helper import NewVulnerabilityDashboardHelper

logger = logging.getLogger(__name__)
random_id = ''.join(random.choices(string.ascii_letters, k=4))
tf_owner_prefix = f'aless-{random_id.lower()}'


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
    root = os.path.join(request.config.rootdir, '../terraform/agents/aws')
    return root


@pytest.fixture(scope='package')
def aws_env_variables(aws_account) -> None:
    """Fixture sets and deletes AWS credentials as env variables."""
    os.environ['AWS_ACCESS_KEY_ID'] = aws_account.aws_access_key_id
    os.environ['AWS_SECRET_ACCESS_KEY'] = aws_account.aws_secret_access_key
    yield
    os.environ.pop('AWS_ACCESS_KEY_ID', None)
    os.environ.pop('AWS_SECRET_ACCESS_KEY', None)


@pytest.fixture(scope="package", params=['single_account'])
def agentless_account_type(request):
    """Used to parametrized Agentless AWS account type. Can be single_account or organization"""
    return request.param


@pytest.fixture(scope="package")
def on_board_agentless_aws_account(aws_account, api_v1_client, agentless_account_type, all_agent_hosts):
    """Fixture to creates/deletes AWS Agentless Configuration integration"""
    cft_helper = CloudformationHelper(aws_credentials=aws_account.credentials)
    logger.info("on_board_agentless_aws_account()")
    account_id = aws_account.aws_account_id
    account_type = "AWS_SIDEKICK" if agentless_account_type == "single_account" else "AWS_SIDEKICK_ORG"
    payload = {
        "TYPE": account_type,
        "ENABLED": 1,
        "IS_ORG": 0,
        "NAME": f"{tf_owner_prefix}_test",
        "DATA": {
            "AWS_ACCOUNT_ID": account_id,
            "SCAN_FREQUENCY": 6,
            "SCAN_HOST_VULNERABILITIES": True,
            "SCAN_CONTAINERS": True,
            "SCAN_STOPPED_INSTANCES": True,
            "SCAN_MULTI_VOLUME": True,
            "SCAN_SHORT_LIVED_INSTANCES": False
        },
        "ENV_GUID": ""
    }
    response = Integrations(api_v1_client).add_agentless_cloud_account(payload=payload)
    assert response.status_code == 201, f"Failed to add agentless aws account, err: {response.text}"
    intg_guid = response.json()['data'][0]["INTG_GUID"]
    stack_id = generate_and_run_aws_agentless_cft(api_v1_client=api_v1_client, intg_guid=intg_guid, aws_credentials=aws_account.credentials)
    yield aws_account
    cft_helper.delete_stack_and_wait(stack_id)
    response = Integrations(api_v1_client).delete_agentless_cloud_account(intg_guid)
    assert response.status_code == 200, f"Failed to delete agentless aws account, err: {response.text}"


def apply_tf_modules(module_list: list[str], module_root: str) -> dict[str, dict]:
    """Deploys list of terraform modules.

    Args:
        module_list: list of TF module names.
        module_root: root folder where all TF modules are located.

    Returns: dict[str, dict]
    """
    hosts = {}
    for tf_module in module_list:
        tf = tftest.TerraformTest(tf_module, module_root)
        try:
            tf.setup()
            os_version = tf_module
            if os_version in windows_tf_modules:
                os_version = os_version.split("windows")[-1]
            owner = f"{tf_owner_prefix}-{os_version}"
            tf.apply(tf_vars={
                'OWNER': owner.replace("_", "-").replace('.', '')
            })
        except Exception:
            logger.exception(f'Failed to deploy TF module {tf_module}')
        finally:
            hosts[tf_module] = {'tf': tf, 'output': tf.output(), 'deployment_time': time.monotonic(), 'deployment_timestamp': datetime.now()}
    return hosts


def destroy_tf_modules(tf_modules: dict) -> None:
    """Destroys list of terraform modules.

    Args:
        module_list: list of TF module names.
        module_root: root folder where all TF modules are located.
    """
    for tf_module in tf_modules:
        try:
            logger.debug(f'Destroying {tf_module=}')
            os_version = tf_module
            if os_version in windows_tf_modules:
                os_version = os_version.split("windows")[-1]
            owner = f"{tf_owner_prefix}-{os_version}"
            tf_modules[tf_module]['tf'].destroy(tf_vars={
                'OWNER': owner.replace("_", "-").replace('.', '')
            })
        except Exception:
            logger.exception(f'Failed to destroy TF module {tf_module}')


@pytest.fixture(scope='package')
def all_agent_tokens(api_v2_client) -> list:
    """Fixture returns list of all agent access tokens"""
    all_tokens = AgentAccessToken(api_v2_client).get_agent_access_tokens().json()['data']
    return all_tokens


@pytest.fixture(scope='package')
def linux_agent_token(api_v2_client, all_agent_tokens):
    """Fixture returns list of all linux agent access tokens."""
    linux_agent_token = None
    for token in all_agent_tokens:
        if token.get('props').get('os') == 'linux':
            linux_agent_token = token.get('accessToken')
    if linux_agent_token:
        return linux_agent_token
    else:
        return AgentTokenHelper(api_v2_client).create_linux_token('fortiqalin1106')


@pytest.fixture(scope='package')
def windows_agent_token(api_v2_client, all_agent_tokens):
    """Fixture returns list of all windows agent access tokens."""
    windows_agent_token = None
    for token in all_agent_tokens:
        if token.get('props').get('os') == 'windows':
            windows_agent_token = token.get('accessToken')
    if windows_agent_token:
        return windows_agent_token
    else:
        return AgentTokenHelper(api_v2_client).create_windows_token('fortiqawin1106')


@pytest.fixture(scope='package')
def linux_agent_hosts(linux_agent_token, agents_tf_root, aws_env_variables):
    """Fixture applies all TF modules for linux agents."""
    hosts = {}
    try:
        os.environ['TF_VAR_AGENT_DOWNLOAD_URL'] = f"https://fortiqa.lacework.net/mgr/v1/download/{linux_agent_token}/install.sh" # noqa
        os.environ['TF_VAR_AGENTLESS_SCAN'] = "true"
        hosts = apply_tf_modules(linux_tf_modules, agents_tf_root)
        yield hosts
    finally:
        destroy_tf_modules(hosts)
        os.environ.pop('TF_VAR_AGENT_DOWNLOAD_URL', None)
        os.environ.pop('TF_VAR_AGENTLESS_SCAN', None)


@pytest.fixture(scope='package')
def windows_agent_hosts(windows_agent_token, agents_tf_root, aws_env_variables):
    """Fixture applies all TF modules for windows agents."""
    os.environ['TF_VAR_AGENT_ACCESS_TOKEN'] = windows_agent_token
    os.environ['TF_VAR_AGENTLESS_SCAN'] = "true"
    hosts = apply_tf_modules(windows_tf_modules, agents_tf_root)
    logger.info(f"{hosts=}")
    try:
        # Giving time for cloud-init on Windows hosts to finish
        for windows_host in hosts:
            tf_output = hosts[windows_host].get('tf').output()
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
        os.environ.pop('TF_VAR_AGENT_ACCESS_TOKEN', None)
        os.environ.pop('TF_VAR_AGENTLESS_SCAN', None)


@pytest.fixture(autouse=True, scope='package')
def all_agent_hosts(windows_agent_hosts, linux_agent_hosts):
    """Fixture returns dictionary with all deployed terraform modules for linux and windows agents."""
    all_hosts = {}
    all_hosts.update(windows_agent_hosts)
    all_hosts.update(linux_agent_hosts)
    return all_hosts


@pytest.fixture(scope='package', params=all_tf_modules)
def os_version(request):
    """Fixture returns one of the supported OS versions"""
    return request.param


@pytest.fixture(scope='package')
def agent_host(os_version, all_agent_hosts):
    """Fixture returns details of deployed agent host based on OS version"""
    return all_agent_hosts.get(os_version)


@pytest.fixture(scope='package')
def agent_host_tf_output(agent_host):
    """Fixture returns TF output of the agent host"""
    return agent_host.get('tf').output()


@pytest.fixture(scope="package", params=packages['java'])
def java_cve_packages(request):
    """Fixture to load Pacakge/CVE data"""
    return request.param


@pytest.fixture(scope="function")
def wait_until_host_is_added(request, api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account):
    """Fixture to wait until host is added inside the Agentless Dashboard"""
    timeout = 18000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    try:
        AgentlessHelper(api_v1_client, deployment_timestamp).wait_until_host_appear(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)
        return datetime.now()
    except TimeoutError as e:
        logger.error(f"TimeoutError found: {e}, mark test cases xfail"
                     f"Host is not added to the Agentless Dashboard"
                     f"Current Time: {datetime.now()}")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} was not found in the Agentless Dashboard: {e}", run=False)
        )
        return None


@pytest.fixture(scope="function")
def wait_until_host_is_scanned(request, api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, wait_until_host_is_added):
    """Fixture to wait until host is scanned inside the Agentless Dashboard"""
    if not wait_until_host_is_added:
        logger.error(f"{os_version} is not added to the Agentless Dashboard")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} was not added in the Agentless Dashboard", run=False)
        )
        return None
    timeout = 18000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    try:
        AgentlessHelper(api_v1_client, deployment_timestamp).wait_until_host_scanned(instance_id=agent_host_instance_id, wait_until=deployment_time+timeout)
        return datetime.now()
    except TimeoutError as e:
        logger.error(f"TimeoutError found: {e}, mark test cases xfail"
                     f"Host is not scanned in the Agentless Dashboard"
                     f"Current Time: {datetime.now()}")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} was not scanned in the Agentless Dashboard: {e}", run=False)
        )
        return None


@pytest.fixture(scope="function")
def wait_until_host_has_any_vulnerability(request, api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, wait_until_host_is_scanned):
    """Fixture to wait until host has more than 0 vulnerabilities"""
    if not wait_until_host_is_scanned:
        logger.error(f"{os_version} is not scanned in the Agentless Dashboard")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} was not scanned in the Agentless Dashboard", run=False)
        )
        return None
    elif "alpine" in os_version:
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} is not supported by Vulnerability dashboard", run=False)
        )
        return None
    timeout = 18000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    try:
        HostVulnerabilitiesHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vulnerability(agent_host_instance_id, wait_until=deployment_time+timeout)
        return datetime.now()
    except TimeoutError as e:
        logger.error(f"TimeoutError found: {e}, mark test cases xfail"
                     f"Host has no vulnerability in the old Vuln Dashboard"
                     f"Current Time: {datetime.now()}")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} has 0 vulnerabilities in the old Vulnerability Dashboard: {e}", run=False)
        )
        return None


@pytest.fixture(scope="function")
def wait_until_host_is_added_to_new_vuln_dashboard(request, api_v1_client, os_version, agent_host, agent_host_tf_output, wait_until_host_is_scanned, on_board_agentless_aws_account):
    """Fixture to wait until host is added to the new Vuln Dashboard"""
    if not wait_until_host_is_scanned:
        logger.error(f"{os_version} is not active in the Agentless Dashboard")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} was not scanned in the Agentless Dashboard", run=False)
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
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} is not added to the new Vulnerability Dashboard: {e}", run=False)
        )
        return None


@pytest.fixture(scope="function")
def wait_until_host_has_any_vulnerability_in_new_vuln_dashboard(request, api_v1_client, os_version, agent_host, agent_host_tf_output, on_board_agentless_aws_account, wait_until_host_is_added_to_new_vuln_dashboard):
    """Fixture to wait until host has more than 0 vulnerabilities in the new Vuln Dashboard"""
    if not wait_until_host_is_added_to_new_vuln_dashboard:
        logger.error(f"{os_version} is not added to the new Vuln Dashboard")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} is not added to the new Vuln Dashboard", run=False)
        )
        return None
    timeout = 18000
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    try:
        NewVulnerabilityDashboardHelper(api_v1_client, deployment_timestamp).wait_until_instance_has_vuln_count(agent_host_instance_id, wait_until=deployment_time+timeout)
        return datetime.now()
    except TimeoutError as e:
        logger.error(f"TimeoutError found: {e}, mark test cases xfail"
                     f"Host has no vulnerability in the new Vuln Dashboard"
                     f"Current Time: {datetime.now()}")
        request.node.add_marker(
            pytest.mark.xfail(reason=f"{os_version} has 0 vulnerabilities in the new Vulnerability Dashboard: {e}", run=False)
        )
        return None
