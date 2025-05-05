import logging
import requests

log = logging.getLogger(__name__)


class TemplateFile:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/TemplateFiles"

    def download_template_file(self, template_file_name: str) -> requests.Response:
        """
        Download CloudFormation template files
        :param template_file_name: AwsConfig, AwsCloudTrail, AwsEksAudit, AwsEksAuditSubscriptionFilter
        """
        log.info(f"download_template_file(): {template_file_name}")
        self._user_api._headers.pop('Content-type')
        response = self._user_api.get(url=f"{self._api_url}/{template_file_name}")
        self._user_api._headers['Content-type'] = 'application/json'
        return response
