import pytest

from fortiqa.libs.lw.apiv2.helpers.agent_token_helper import AgentTokenHelper
from fortiqa.libs.lw.apiv2.api_client.agent_access_tokens.agent_access_tokens import AgentAccessToken
from fortiqa.libs.lw.apiv1.api_client.agent_token.agent_token import AgentToken


@pytest.fixture(scope='session')
def all_agent_tokens(api_v2_client) -> list:
    """Fixture returns list of all agent access tokens"""
    all_tokens = AgentAccessToken(api_v2_client).get_agent_access_tokens().json()['data']
    return all_tokens


@pytest.fixture(scope='session')
def linux_agent_token(api_v2_client, all_agent_tokens):
    """Fixture returns a linux agent access token."""
    linux_agent_token = None
    for token in all_agent_tokens:
        if token.get('props').get('os') == 'linux':
            linux_agent_token = token.get('accessToken')
            return linux_agent_token
    return AgentTokenHelper(api_v2_client).create_linux_token('fortiqalin1106')


@pytest.fixture(scope='session')
def linux_agent_token_with_caa(api_v2_client, all_agent_tokens, api_v1_client):
    """Fixture returns a linux agent access token."""
    linux_agent_token = None
    for token in all_agent_tokens:
        if token.get('props').get('os') == 'linux':
            linux_agent_token = token.get('accessToken')
            token_configuration = AgentToken(api_v1_client).get_agent_token_config_by_access_token(access_token=linux_agent_token).json()
            caa_enabled = token_configuration.get("codeaware").get("enable")  # experimental means host, all means host and container, false means disabled
            if caa_enabled and caa_enabled != "false":
                return linux_agent_token
    created_agent_access_token = AgentTokenHelper(api_v2_client).create_linux_token('fortiqalin1106')
    AgentToken(api_v1_client).change_agent_token_codeaware_configuration(access_token=created_agent_access_token, codeaware_option="host")
    return created_agent_access_token


@pytest.fixture(scope='session')
def linux_agent_token_with_caa_vulnwatch(api_v2_client, all_agent_tokens, api_v1_client):
    """Fixture returns a linux agent access token with CAA and vulnwatch enabled."""
    linux_agent_token = None
    for token in all_agent_tokens:
        if token.get('props').get('os') == 'linux':
            linux_agent_token = token.get('accessToken')
            token_configuration = AgentToken(api_v1_client).get_agent_token_config_by_access_token(access_token=linux_agent_token).json()
            caa_enabled = token_configuration.get("codeaware").get("enable")  # experimental means host, all means host and container, false means disabled

            if not caa_enabled or caa_enabled == "false":
                continue

            vulnwatch_enabled = token_configuration.get("codeaware").get("vulnwatch")
            if not vulnwatch_enabled or vulnwatch_enabled == "false":
                continue

            return linux_agent_token

    created_agent_access_token = AgentTokenHelper(api_v2_client).create_linux_token('fortiqa-linux-vulnwatch')
    AgentToken(api_v1_client).change_agent_token_codeaware_configuration(access_token=created_agent_access_token, codeaware_option="vulnwatch")
    return created_agent_access_token


@pytest.fixture(scope='session')
def windows_agent_token(api_v2_client, all_agent_tokens):
    """Fixture returns a windows agent access token."""
    windows_agent_token = None
    for token in all_agent_tokens:
        if token.get('props').get('os') == 'windows':
            windows_agent_token = token.get('accessToken')
            return windows_agent_token
    return AgentTokenHelper(api_v2_client).create_windows_token('fortiqawin1106')
