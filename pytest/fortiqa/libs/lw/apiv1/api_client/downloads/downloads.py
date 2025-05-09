import logging
import requests

from fortiqa.libs.lw.apiv1.api_client.api_v1_client import ApiV1Client

logger = logging.getLogger(__name__)


class Downloads:

    def __init__(self, api_v1_client: ApiV1Client) -> None:
        """Initializes the AccountSetting class.

        Args:
            api_v1_client (api_v1_client): An instance of the API v1 client for sending requests.
        """
        self._user_api = api_v1_client
        self._api_url = f"{api_v1_client.url}/downloads"

    def download_template_file(self, template_file_name: str, intgGuid: str) -> requests.Response:
        """
        Download CloudFormation template files
        :param template_file_name: Template file name, e.g. lacework-aws-agentless-direct-ng-auto.json
        :param intgGuid: intgGuid of the cloud account
        """
        logger.info(f"download_template_file(): {template_file_name}")
        response = self._user_api.get(url=f"{self._api_url}/templates/{template_file_name}?intgGuid={intgGuid}")
        return response
