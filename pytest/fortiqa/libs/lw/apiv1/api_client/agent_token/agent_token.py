import logging
import requests

from fortiqa.libs.lw.apiv1.api_client.api_v1_client import ApiV1Client
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response

logger = logging.getLogger(__name__)


class AgentToken:
    """A class to interact with the Agent Token V1 API"""

    def __init__(self, api_v1_client: ApiV1Client) -> None:
        """Initializes the AgentToken class.

        Args:
            api_v1_client (api_v1_client): An instance of the API v1 client for sending requests.
        """
        self._user_api = api_v1_client
        self._api_url = f"{api_v1_client.url}/tokens"

    def get_all_agent_tokens(self) -> requests.Response:
        """Retrieves all agent tokens from the API.

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.info("get_all_agent_tokens()")
        response = self._user_api.get(url=self._api_url)
        check_and_return_json_from_response(response)
        logger.debug(f"Agent Token response: {response.text}")
        return response

    def get_agent_token_config_by_access_token(self, access_token: str) -> requests.Response:
        """Retrieves a specific agent token configuration by its access token.

        Args:
            access_token: Agent access token
        Returns:
            requests.Response: The agent token's configuration
        """
        logger.info(f"get_agent_token_config_by_access_token({access_token=})")
        url = f"{self._user_api.url}/agentctrl/config/access-token"
        response = self._user_api.get(url=f"{url}?token={access_token}")
        check_and_return_json_from_response(response)
        logger.debug(f"Agent Token with {access_token=} configuration: {response.text}")
        return response

    def change_agent_token_codeaware_configuration(self, access_token: str, codeaware_option: str) -> None:
        """Change a specific agent token codeaware configuration by its access token.

        Args:
            access_token: Agent access token
            codeaware_option: Active package detection option, could be "host", "host_and_container" or "disable"
        """
        logger.info(f"change_agent_token_codeaware_configuration({access_token=})")
        previous_config = self.get_agent_token_config_by_access_token(access_token).json()
        if codeaware_option == "disable":
            previous_config['codeaware']['enable'] = "false"
        elif codeaware_option == "host":
            previous_config['codeaware']['enable'] = "experimental"
        elif codeaware_option == "vulnwatch":
            previous_config['codeaware']['enable'] = "all"
            previous_config['codeaware']['vulnwatch'] = 'true'
        elif codeaware_option == "all":
            previous_config['codeaware']['enable'] = "all"
        else:
            logger.warning(f"Invalid codeaware_option: {codeaware_option}, defaulting to disabled")
            previous_config['codeaware']['enable'] = "false"

        url = f"{self._user_api.url}/agentctrl/config/access-token"
        response = self._user_api.put(url=f"{url}?token={access_token}", payload=previous_config)
        assert response.status_code == 200, f"Failed to update agent token {access_token} configuration"
        # system_config_url = f"{self._user_api.url}/agentctrl/config/syscall/default"
        # system_config_payload = self._user_api.get(url=f"{system_config_url}?token={access_token}").json()
        # response = self._user_api.put(url=f"{system_config_payload}?token={access_token}", payload=system_config_payload)
        # assert response.status_code == 200, f"Failed to update agent token {access_token} syscall configuration"
        return
