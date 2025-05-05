import pytest
import logging
import copy

from fortiqa.libs.lw.apiv1.payloads import AgentFilter
from fortiqa.libs.lw.apiv1.helpers.agents_helper import AgentsHelper
from fortiqa.tests.e2e.agents.host_versions import windows_tf_modules, linux_tf_modules
from fortiqa.libs.lw.apiv1.api_client.new_agent_dashboard.new_agent_dashboard import NewAgentDashboard

logger = logging.getLogger(__name__)


def test_host_is_added_to_new_agent_dashboard(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test the host is added to the new agent dashboard

    Given: all hosts are deployed
    When: use APIv1 new Agent dashboard API to list all added hosts
    Then: assert the tested host appears inside the API response
    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    logger.info(f'test_host_is_added_to_new_agent_dashboard({os_version=})')
    timeout = 9600
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    agents_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    agents_helper.wait_until_agent_is_added_to_new_dashboard(agent_host_instance_id, wait_until=deployment_time+timeout)


def test_host_is_active_in_new_agent_dashboard(api_v1_client, os_version, csp, agent_host, agent_host_tf_output):
    """Test host is active inside the new Agent dashboard.

    Given: all agents are deployed
    When: getting list of available agents using agent dashboard query V1 API
    Then: assert agent is active.

    Args:
      api_v1_client: LW API v1 client
      os_version: agent distro version and tf module folder name under terraform/agents/{csp}/, e.g. ubuntu2404
      csp: CSP name e.g. aws, gcp, azure
      agent_host: tf module deployed for the given os_version and csp.
    """
    logger.info(f'test_host_is_active({os_version=})')
    timeout = 9600
    deployment_time = agent_host['deployment_time']
    deployment_timestamp = agent_host['deployment_timestamp']
    agent_host_instance_id = agent_host_tf_output['agent_host_instance_id']
    AgentsHelper(api_v1_client, deployment_timestamp).wait_until_agent_is_active_in_new_agent_dashboard(agent_host_instance_id, wait_until=deployment_time+timeout)


def compare_tf_output_to_response(tf_output: dict, host_details: dict) -> list:
    """
    Helper function to compare TF output to the API response

    :param tf_output: Terraform output as a dictionary
    :param host_details: API response from new agent dashboard
    :return: A list contains error messages
    """
    error_messages = []
    agent_host_instance_id = tf_output['agent_host_instance_id']
    for field in tf_output:
        output_value = tf_output[field]
        if field == "agent_host_private_ip":
            if 'IP_ADDRESS' in host_details:
                if host_details['IP_ADDRESS'] != output_value:
                    error_messages.append(f"Private IP collected is {host_details['IP_ADDRESS']}, but expected {output_value}")
            else:
                error_messages.append(f"Fail to collect private IP address of instance {agent_host_instance_id}")
            if 'InternalIp' in host_details['MACHINE_TAGS']:
                if host_details['MACHINE_TAGS']['InternalIp'] != output_value:
                    error_messages.append(f"Private IP collected in machine tags is {host_details['MACHINE_TAGS']['InternalIp']}, but expected {output_value}")
            else:
                error_messages.append(f"Fail to collect machine tag private IP address of instance {agent_host_instance_id}")
        elif field == "agent_host_instance_id":
            if 'InstanceId' in host_details['MACHINE_TAGS']:
                if host_details['MACHINE_TAGS']['InstanceId'] != output_value:
                    error_messages.append(f"InstanceId collected in machine tags is {host_details['MACHINE_TAGS']['InstanceId']}, but expected {output_value}")
            else:
                error_messages.append(f"Fail to collect machine tag InstanceId of instance {agent_host_instance_id}")
        elif field == "agent_ami_id":
            if 'AmiId' in host_details['MACHINE_TAGS']:
                if host_details['MACHINE_TAGS']['AmiId'] != output_value:
                    error_messages.append(f"AmiId collected in machine tags is {host_details['MACHINE_TAGS']['AmiId']}, but expected {output_value}")
            else:
                error_messages.append(f"Fail to collect machine tag AmiId of instance {agent_host_instance_id}")
        elif field == "agent_vpc_id":
            if 'VpcId' in host_details['MACHINE_TAGS']:
                if host_details['MACHINE_TAGS']['VpcId'] != output_value:
                    error_messages.append(f"VpcId collected in machine tags is {host_details['MACHINE_TAGS']['VpcId']}, but expected {output_value}")
            else:
                error_messages.append(f"Fail to collect machine tag VpcId of instance {agent_host_instance_id}")
        elif field == "agent_subnet_id":
            if 'SubnetId' in host_details['MACHINE_TAGS']:
                if host_details['MACHINE_TAGS']['SubnetId'] != output_value:
                    error_messages.append(f"SubnetId collected in machine tags is {host_details['MACHINE_TAGS']['SubnetId']}, but expected {output_value}")
            else:
                error_messages.append(f"Fail to collect machine tag SubnetId of instance {agent_host_instance_id}")
        elif field == "agent_host_public_ip":
            if 'ExternalIp' in host_details['MACHINE_TAGS']:
                if host_details['MACHINE_TAGS']['ExternalIp'] != output_value:
                    error_messages.append(f"ExternalIp collected in machine tags is {host_details['MACHINE_TAGS']['ExternalIp']}, but expected {output_value}")
            else:
                error_messages.append(f"Fail to collect machine tag ExternalIp of instance {agent_host_instance_id}")
    agent_token = tf_output.get("agent_token", "")
    if 'TOKEN' in host_details:
        if host_details['TOKEN'] not in agent_token:
            error_messages.append(f"Agent Token collected is {host_details['TOKEN']}, but expected {agent_token}")
    else:
        error_messages.append(f"Fail to collect agent token of instance {agent_host_instance_id}")
    if 'LwTokenShort' in host_details['MACHINE_TAGS']:
        if host_details['MACHINE_TAGS']['LwTokenShort'] not in agent_token:
            error_messages.append(f"LwTokenShort collected in machine tags is {host_details['MACHINE_TAGS']['LwTokenShort']}, but expected {agent_token}")
    else:
        error_messages.append(f"Fail to collect machine tag LwTokenShort of instance {agent_host_instance_id}")
    return error_messages


@pytest.mark.parametrize('csp', [
        'aws',
        pytest.param('azure', marks=pytest.mark.xfail(reason='https://lacework.atlassian.net/browse/LXAGNT-204')),
        'gcp',
    ], indirect=True)
def test_new_agent_dashboard_details_by_hostname_and_ip(api_v1_client, os_version, csp, agent_host, terraform_owner, linux_agent_token, windows_agent_token, agent_host_tf_output):
    """Test the new Agent Dashboard V1 API filtered by hostname and IP returns correct details of the hosts

    Given: all agents are deployed
    When: Return the details collected by the agent
    Then: assert information returned by API is correct

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed agent terraform modules
      linux_agent_token: Linux agent token when deploying the agent inside Linux hosts
      windows_agent_token: Windows agent token when deploying the agent inside Windows hosts
    """
    logger.info(f'test_new_agent_dashboard_details({os_version=})')
    deployment_timestamp = agent_host['deployment_timestamp']
    tf_output = agent_host_tf_output
    agent_private_ip = tf_output['agent_host_private_ip']
    agent_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    payload = copy.deepcopy(agent_helper.new_dashboard_payload_template)
    payload['Filters'][AgentFilter.HOSTNAME] = [{
        "value": terraform_owner,
        "filterGroup": "include"
    }]
    payload['Filters'][AgentFilter.IP_ADDRESS] = [{
        "value": agent_private_ip,
        "filterGroup": "include"
    }]
    response = NewAgentDashboard(api_v1_client).get_agent_inventory(payload=payload)
    assert response.status_code == 200, f"Failed to get the agent inventory, error: {response.text}"
    logger.info(f"Agent dashboard API response: {response.json()}")
    assert response.json()['data'], f"There is no agent in the dashboard for hostname={terraform_owner} and ip={agent_private_ip}"
    host_details = response.json()['data'][0]
    agent_token = linux_agent_token if os_version in linux_tf_modules else windows_agent_token
    mutable_tf_output = dict(tf_output)
    mutable_tf_output['agent_token'] = agent_token
    error_messages = compare_tf_output_to_response(mutable_tf_output, host_details)
    logger.debug(f"{error_messages=}")
    if os_version in windows_tf_modules:
        pytest.xfail(reason="https://lacework.atlassian.net/browse/LXAGNT-192")
    assert not error_messages, error_messages


def test_new_agent_dashboard_details_by_instance_id(api_v1_client, os_version, csp, agent_host, terraform_owner, linux_agent_token, windows_agent_token, agent_host_tf_output):
    """Test the new Agent Dashboard V1 API filtered by instance_id returns correct details of the hosts

    Given: all agents are deployed
    When: Return the details collected by the agent
    Then: assert information returned by API is correct

    Args:
      api_v1_client: LW API v1 client
      agent_version: agent distro version to test
      all_agent_hosts: list of all deployed agent terraform modules
      linux_agent_token: Linux agent token when deploying the agent inside Linux hosts
      windows_agent_token: Windows agent token when deploying the agent inside Windows hosts
    """
    if csp == 'azure':
        pytest.xfail(reason="https://lacework.atlassian.net/browse/LXAGNT-204")
    logger.info(f'test_new_agent_dashboard_details({os_version=})')
    deployment_timestamp = agent_host['deployment_timestamp']
    tf_output = agent_host_tf_output
    agent_token = linux_agent_token if os_version in linux_tf_modules else windows_agent_token
    agent_host_instance_id = tf_output['agent_host_instance_id']
    agent_helper = AgentsHelper(api_v1_client, deployment_timestamp)
    host_details = agent_helper.fetch_agent_info_by_instance_id_in_new_dashboard(agent_host_instance_id)[0]
    mutable_tf_output = dict(tf_output)
    mutable_tf_output['agent_token'] = agent_token
    error_messages = compare_tf_output_to_response(mutable_tf_output, host_details)
    logger.debug(f"{error_messages=}")
    if os_version in windows_tf_modules:
        pytest.xfail(reason="https://lacework.atlassian.net/browse/LXAGNT-192")
    assert not error_messages, error_messages
