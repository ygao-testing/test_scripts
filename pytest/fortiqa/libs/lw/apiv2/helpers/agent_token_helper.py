import logging

from fortiqa.libs.lw.apiv2.api_client.agent_access_tokens.agent_access_tokens import AgentAccessToken

logger = logging.getLogger(__name__)


class AgentTokenHelper:
    def __init__(self, user_api):
        self.agent_token_api = AgentAccessToken(user_api)

    def create_windows_token(self, name: str) -> str:
        """Todo"""
        payload = {
            "props": {
                "description": name,
                "os": "windows"
            },
            "tokenAlias": name,
            "tokenEnabled": 1
        }
        response = self.agent_token_api.create_agent_access_token(payload)
        return response.json()['data']['accessToken']

    def create_linux_token(self, name: str) -> str:
        """Todo"""
        payload = {
            "props": {
                "description": name,
                "os": "linux"
            },
            "tokenAlias": name,
            "tokenEnabled": 1
        }
        response = self.agent_token_api.create_agent_access_token(payload)
        return response.json()['data']['accessToken']
