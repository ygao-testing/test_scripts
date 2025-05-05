import os
import time
import random
import string
import logging
import pytest
import tftest

from datetime import datetime
from fortiqa.tests.e2e.agents.host_versions import linux_tf_modules, supported_csps
from fortiqa.tests.e2e.integrations.cloud_accounts.helpers import generate_and_run_aws_agentless_cft
from fortiqa.libs.aws.cloudformation import CloudformationHelper
from fortiqa.libs.lw.apiv1.api_client.cloud_accounts.integrations import Integrations

logger = logging.getLogger(__name__)
random_id = ''.join(random.choices(string.ascii_letters, k=4))
tf_owner_prefix = f'agent-{random_id.lower()}'


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


@pytest.fixture(scope="package")
def terraform_owner(os_version):
    """Fixture to return the tf_owner value"""
    owner = f"{tf_owner_prefix}-{os_version}"
    return owner.replace("_", "-").replace('.', '')


@pytest.fixture(scope='package')
def agents_tf_root(request) -> str:
    """Fixture returns root folder for lacework provider TF modules."""
    root = os.path.join(request.config.rootdir, '../terraform/agents/')
    print(f'{root=}')
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
                    owner = f"{tf_owner_prefix}-{os_version}"
                    tf.apply(tf_vars={
                        # gcp does not allow underscores and . in owner name
                        'OWNER': owner.replace("_", "-").replace('.', '')
                    })
                except Exception:
                    logger.exception(f'Failed to deploy TF module {tf_module}')
                finally:
                    hosts[tf_module][csp] = {'tf': tf, 'deployment_time': time.monotonic(), 'deployment_timestamp': datetime.now()}
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
                    logger.info(f'Destroying {tf_module=}')
                    os_version = tf_module
                    owner = f"{tf_owner_prefix}-{os_version}"
                    tf_modules[tf_module][csp]['tf'].destroy(tf_vars={
                        'OWNER': owner.replace("_", "-").replace('.', '')
                    })
                except Exception:
                    logger.exception(f'Failed to destroy TF module {tf_module}')


@pytest.fixture(scope='package')
def linux_agent_hosts(linux_agent_token_with_caa, agents_tf_root, aws_env_variables):
    """Fixture applies all TF modules for linux agents."""
    hosts = {}
    try:
        os.environ['TF_VAR_AGENT_DOWNLOAD_URL'] = f"https://fortiqa.lacework.net/mgr/v1/download/{linux_agent_token_with_caa}/install.sh" # noqa
        hosts = apply_tf_modules(linux_tf_modules, supported_csps, agents_tf_root)
        yield hosts
    finally:
        destroy_tf_modules(hosts)
        if 'TF_VAR_AGENT_DOWNLOAD_URL' in os.environ:
            del os.environ['TF_VAR_AGENT_DOWNLOAD_URL']


@pytest.fixture(autouse=True, scope='package')
def all_agent_hosts(linux_agent_hosts):
    """Fixture returns dictionary with all deployed terraform modules for linux and windows agents."""
    all_hosts = {}
    all_hosts.update(linux_agent_hosts)
    return all_hosts


@pytest.fixture(scope='package', params=supported_csps)
def csp(request):
    """Fixture returns one of the supported CSPs"""
    return request.param


@pytest.fixture(scope='package', params=linux_tf_modules)
def os_version(request):
    """Fixture returns one of the supported OS versions"""
    return request.param


@pytest.fixture(scope='package', params=linux_tf_modules)
def linux_os_version(request):
    """Fixture returns one of the supported Linux OS versions"""
    return request.param


@pytest.fixture(scope='package')
def agent_host(csp, os_version, all_agent_hosts):
    """Fixture returns details of deployed agent host based on CSP and OS version"""
    if (host := all_agent_hosts.get(os_version).get(csp)) is None:
        pytest.skip(f'TF module {csp}/{os_version} was not found among deployed TF resources')
    else:
        return host


@pytest.fixture(scope='package')
def linux_agent_host(csp, linux_os_version, all_agent_hosts):
    """Fixture returns details of deployed agent host based on CSP and OS version"""
    if (host := all_agent_hosts.get(linux_os_version).get(csp)) is None:
        pytest.skip(f'TF module {csp}/{linux_os_version} was not found among deployed TF resources')
    else:
        return host


@pytest.fixture(scope='package')
def agent_host_tf_output(agent_host):
    """Fixture returns TF output of the agent host"""
    return agent_host.get('tf').output()
