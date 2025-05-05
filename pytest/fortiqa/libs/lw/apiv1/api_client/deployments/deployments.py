import time
import json
import random
import string
import logging
import requests
import tempfile
from typing import Dict, Any
from json.decoder import JSONDecodeError
from requests.exceptions import ChunkedEncodingError
from functools import wraps

logger = logging.getLogger(__name__)
char_list = string.ascii_lowercase + string.digits


class Deployments:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f'{user_api.url}/deployments'

    def generate_channel_id(self) -> str:
        """
        Generates a random channel ID.

        The channel ID is in the format of 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' where
        each 'x' is a random character from the list of lowercase ascii letters and
        digits.

        The actual length of the channel ID is 36 characters.

        :return: A random channel ID.
        :rtype: str
        """
        def gen_word(word_len: int) -> str:
            return ''.join(random.choice(char_list) for _ in range(word_len))

        return '-'.join([gen_word(length) for length in [8, 4, 4, 4, 12]])

    def run_discovery(self, payload: dict, channel: str) -> requests.Response:
        """
        Run a discovery using the provided payload and channel.

        This endpoint starts a discovery process based on the provided payload.
        The payload is expected to be a JSON object with the configuration for the
        discovery.

        :param payload: The configuration for the discovery as a JSON object.
        :param channel: The channel to use for this discovery.
        :return: The response from the API.
        :rtype: requests.Response
        """
        response = self._user_api.post(
            url=f'{self._api_url}/discover?channel={channel}',
            payload=payload,
        )
        return response

    def run_integration(self, payload: dict) -> requests.Response:
        """
        Run an integration using the provided payload.

        This endpoint starts an integration process based on the provided payload.
        The payload is expected to be a JSON object with the configuration for the
        integration.

        :param payload: The configuration for the integration as a JSON object.
        :return: The response from the API.
        :rtype: requests.Response
        """
        response = self._user_api.post(
            url=f"{self._api_url}",
            payload=payload,
        )
        return response

    @staticmethod
    def retry_on_chunked_encoding(max_retries=3, initial_delay=1):
        """
        Decorator to retry a function call on ChunkedEncodingError.

        This decorator wraps a function and retries the specified number of times
        after an initial attempt, applying exponential backoff between retries.

        Args:
            max_retries (int): The maximum number of retries after the initial attempt. Default is 3.
            initial_delay (int): The initial delay in seconds before the first retry. Default is 1.

        Returns:
            function: The wrapped function with retry logic.
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                retries = 0
                while retries < max_retries:
                    try:
                        return func(*args, **kwargs)
                    except ChunkedEncodingError as e:
                        retries += 1
                        if retries == max_retries:
                            raise Exception(f"Max retries ({max_retries}) exceeded for SSE connection: {str(e)}")
                        delay = initial_delay * (2 ** (retries - 1)) + random.uniform(0, 1)
                        logger.warning(f"ChunkedEncodingError occurred. Attempt {retries}/{max_retries}. "
                                       f"Retrying in {delay:.2f} seconds...")
                        time.sleep(delay)
                return func(*args, **kwargs)
            return wrapper
        return decorator

    @retry_on_chunked_encoding(max_retries=3, initial_delay=1)
    def get_sse(self, channel: str, timeout: int = 300):
        """
        Get the result of a deployment from the Server-Sent Events (SSE) API.

        The SSE API returns a stream of messages and a final result. This function
        blocks until the result is received and then returns it.

        :param channel: The channel to use for this discovery.
        :param timeout: Request timeout in seconds (default: 300)
        :return: A dictionary with the final result of the discovery.
        :rtype: Dict[str, Any]
        :raises: requests.exceptions.Timeout: If the request times out
        """
        sse_result: Dict[str, Any] = {
            'messages': [],
            'results': {},
        }
        try:
            with self._user_api.get(
                    url=f'{self._api_url}/sse?channel={channel}',
                    timeout=timeout,
                    stream=True,
            ) as resp:
                time.sleep(20)
                for line in resp.iter_lines():
                    if line and line.startswith(b'data: '):
                        try:
                            data = line.split(b'data: ')[1]
                            data_json = json.loads(data)
                            # discovery use 'results' in response
                            if 'results' in data_json:
                                sse_result['results'] = data_json['results']
                                logger.debug(f'results: {sse_result["results"]}')
                                return sse_result
                            # integration use 'done' in response
                            elif 'done' in data_json:
                                logger.debug(f'done: {data_json["done"]}')
                                sse_result['done'] = data_json['done']
                                return sse_result
                            elif 'message' in data_json:
                                logger.debug(f'message: {data_json["message"]}')
                                sse_result['messages'].append(data_json['message'])
                        except JSONDecodeError:
                            logger.debug(f'{line} was not a JSON')
                        except Exception as e:
                            logger.debug(f'{e=}')
        except requests.exceptions.Timeout:
            logger.error(f"SSE request timed out after {timeout} seconds for {channel=}")
            raise
        if not sse_result:
            raise Exception(f"No result field was found in /SSE API response for {channel=}")

    def create_integration(self, payload: dict) -> requests.Response:
        """
        Create a new integration.

        :param payload: The integration data to pass to the API.
        :return: The response from the API.
        :rtype: requests.Response
        """
        response = self._user_api.post(url=self._api_url, payload=payload)
        return response

    def pull_integration(self, deployment_id: str, max_attempts: int = 60, sleep_interval: int = 10) -> dict:
        """
        Continuously pull integrations and check their status until complete or failed.

        :param deployment_id: The ID of the deployment to pull integrations from.
        :param max_attempts: Maximum number of attempts to pull integrations (default: 60).
        :param sleep_interval: Time to sleep between attempts in seconds (default: 10).
        :return: The final response data.
        :rtype: dict
        """
        for attempt in range(max_attempts):
            response = self._user_api.get(url=f'{self._api_url}/{deployment_id}')

            if response.status_code != 200:
                raise Exception(f"Pull integrations failed with status code: {response.status_code}")

            data = response.json().get('data', {})
            status = data.get('status', '').lower()

            if status == 'succeeded':
                return data
            elif status == 'failed':
                logger.error("Integration failed")
                return data
            elif status == 'rolled-back':
                logger.info("Integration rolled back")
                return data
            elif status == 'running':
                print(f"Integration still running. Attempt {attempt + 1}/{max_attempts}")
                time.sleep(sleep_interval)
            else:
                raise Exception(f"Unknown status: {status}")

        raise Exception(f"Integration did not complete within {max_attempts} attempts")

    def delete_integration(self, deployment_id: str, payload: dict) -> requests.Response:
        """
        Delete an integration, roll back all resources created during the integration.

        :param deployment_id: The ID of the integration to delete.
        :return: The response from the API.
        :rtype: requests.Response
        """
        response = self._user_api.delete(url=f'{self._api_url}/{deployment_id}', payload=payload)
        return response

    def get_integration(self, deployment_id: str) -> requests.Response:
        """
        Get the details of an integration.

        :param deployment_id: The ID of the integration to get.
        :return: The response from the API.
        :rtype: requests.Response
        """
        response = self._user_api.get(url=f'{self._api_url}/{deployment_id}')
        return response

    def download_integration_tf_files(self, deployment_id: str, workspace_id: str) -> str:
        """
        Download Terraform files for an integration and save to a temporary file.

        :param deployment_id: The ID of the integration to download Terraform files for.
        :param workspace_id: The ID of the workspace to download Terraform files for.
        :return: The path to the temporary file where the Terraform files are saved.
        :rtype: str
        """
        response = self._user_api.get(url=f'{self._api_url}/{deployment_id}/download?workspace_id={workspace_id}', stream=True)

        if response.status_code != 200:
            response.raise_for_status()

        # Create a temporary file
        temp_file_name = f"{deployment_id}_{workspace_id}"
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.gz', prefix=temp_file_name)
        temp_file_path = temp_file.name

        # Write the content to the temporary file
        with open(temp_file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        logger.info(f"Downloaded Terraform files for deployment {deployment_id} workspace {workspace_id}: {temp_file_path}")
        return temp_file_path
