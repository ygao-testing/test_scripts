import time
import string
import logging
import requests

logger = logging.getLogger(__name__)
char_list = string.ascii_lowercase + string.digits


class ECROnboarding:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f'{user_api.url}/integrations/containerRegistries'

    def run_onboarding(self, payload: dict) -> requests.Response:
        """
        Run a integration of ECR using the provided payload and channel.

        This endpoint starts a integration process based on the provided payload.

        :param payload: The configuration for the integration as a JSON object.
        :return: The response from the API.
        :rtype: requests.Response
        """
        response = self._user_api.post(
            url=self._api_url,
            payload=payload,
        )
        return response

    def get_ecr_onboarding(self, id: str) -> requests.Response:
        """
        Get the details of an ECR onboarding integration.

        :param id: The ID of the integration to get.
        :return: The response from the API.
        :rtype: requests.Response
        """
        response = self._user_api.get(url=f'{self._api_url}/{id}')
        return response

    def pull_ecr_onboarding(self, id: str, max_attempts: int = 60) -> requests.Response:
        """
        Pull the result of an ECR onboarding integration from API.

        This function blocks until the result is received and then returns it.

        :param id: The ID of the integration to get.
        :param max_attempts: The maximum number of times to attempt to get the result.
        :return: The response from the API.
        :rtype: requests.Response
        """
        for attempt in range(max_attempts):
            response = self._user_api.get(url=f'{self._api_url}/{id}')

            if response.status_code != 200:
                raise Exception(f"Pull integrations failed with status code: {response.status_code}")

            data = response.json().get('data', [])
            assert isinstance(data, list)
            data = data[0]

            status = data.get('STATE', None)
            if status:
                return data
            # if no status field, wait and try again
            logger.info(f"ECR onboarding still running. Attempt {attempt + 1}/{max_attempts}")
            time.sleep(5)
        raise Exception(f"Pull ecr onboarding integrations failed with status code: {response.status_code}")

    def delete_ecr_onboarding(self, id: str) -> requests.Response:
        """
        Delete an ECR onboarding integration.

        :param id: The ID of the integration to delete.
        :return: The response from the API.
        :rtype: requests.Response
        """
        response = self._user_api.delete(url=f'{self._api_url}/{id}')
        return response
