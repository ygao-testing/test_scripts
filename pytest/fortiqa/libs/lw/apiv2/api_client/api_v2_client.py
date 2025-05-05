import json
import logging
import requests
import time
from functools import wraps
from requests.exceptions import ConnectionError
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

log = logging.getLogger(__name__)

disable_warnings(InsecureRequestWarning)


def retry_on_connection_error(retries=3):
    """Decorator to retry a method on ConnectionError, reinitializing the session .

    This decorator wraps a function and retries the specified number of times after an initial attempt.
    Each retry applies exponential backoff and session reinitialization.

    Args:
        retries (int): The number of retries after the initial attempt. Default is 3.

    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            try:

                return func(self, *args, **kwargs)
            except ConnectionError as e:
                log.error(f"ConnectionError on initial attempt: {e}")
                log.info(f"Beginning retries with up to {retries} attempts...")

            # Retry attempts if initial attempt fails
            for attempt in range(1, retries + 2):
                try:
                    log.info(f"Retry attempt {attempt}/{retries}")
                    return func(self, *args, **kwargs)
                except ConnectionError as e:
                    log.error(f"ConnectionError on retry attempt {attempt}/{retries}: {e}")
                    # Only retry if there are more attempts left
                    if attempt < (retries + 1):
                        self._session.close()
                        backoff_time = 2 ** attempt
                        log.info(f"Applying backoff, waiting {backoff_time} seconds before retrying...")
                        time.sleep(backoff_time)
                        log.info("Reinitializing session.")
                        self._create_new_session()
                    else:
                        # Last attempt has failed; raise the error
                        raise ConnectionError(f"Failed to connect after {retries + 1} total attempts: {e}")

        return wrapper

    return decorator


class APIV2Client(object):

    def __init__(self, account: str, lw_api_key: str, lw_secret: str) -> None:
        self.url = f"https://{account}.lacework.net/api/v2"  # noqa: E231
        self.user_secret = lw_secret
        self.user_keyid = lw_api_key
        self._create_new_session()

    def __enter__(self):
        return self

    def __exit__(self, exception_type,
                 exception_value, exception_traceback) -> None:
        self._session.close()

    def _create_new_session(self, expiry_time: int = 36000):
        self._session = requests.session()
        self._headers = {
            'X-LW-UAKS': self.user_secret,
            'Content-type': 'application/json'
        }
        payload = json.dumps({
            "keyId": self.user_keyid,
            'expiryTime': expiry_time
        })
        response = self._session.post(f"{self.url}/access/tokens", headers=self._headers, data=payload)
        assert response.status_code == 201, f"Failed to get access token: {response.status_code} {response.text}"
        self._access_token = response.json()['token']
        self._headers['Authorization'] = self._access_token

    def get_no_token_refresh(self, url, params=None, allow_redirects=True) -> requests.models.Response:
        """Send GET request in current session without token refresh, used for api key testing"""
        response = self._session.get(url, headers=self._headers, verify=True, params=params,
                                     allow_redirects=allow_redirects)
        log.debug(f"GET API response: {response}")
        return response

    @retry_on_connection_error(retries=3)
    def get(self, url, params=None, allow_redirects=True) -> requests.models.Response:
        """Send GET request in current session"""
        response = self._session.get(url, headers=self._headers, verify=True, params=params,
                                     allow_redirects=allow_redirects)
        if response.status_code == 401 or response.status_code == 403:
            self._session.close()
            self._create_new_session()
            response = self._session.get(url, headers=self._headers, verify=True, params=params,
                                         allow_redirects=allow_redirects)
        log.debug(f"GET API response: {response}")
        return response

    @retry_on_connection_error(retries=3)
    def post(self, url, payload=None, params=None) -> requests.models.Response:
        """Send POST request in current session"""
        response = self._session.post(url=url, data=json.dumps(payload), headers=self._headers,
                                      params=params,
                                      verify=True)
        if response.status_code == 401 or response.status_code == 403:
            self._session.close()
            self._create_new_session()
            response = self._session.post(url=url, data=json.dumps(payload),
                                          headers=self._headers,
                                          params=params,
                                          verify=True)
        log.debug(f"POST API response: {response}")
        return response

    @retry_on_connection_error(retries=3)
    def put(self, url, payload=None, params=None) -> requests.models.Response:
        """Send PUT request in current session"""
        response = self._session.put(url=url, data=json.dumps(payload),
                                     headers=self._headers,
                                     verify=True, params=params)
        if response.status_code == 401 or response.status_code == 403:
            self._session.close()
            self._create_new_session()
            response = self._session.put(url=url, data=json.dumps(payload),
                                         headers=self._headers,
                                         verify=True, params=params)
        log.debug(f"PUT API response status code: '{response.status_code}', text: '{response.text}'")
        return response

    @retry_on_connection_error(retries=3)
    def delete(self, url, payload=None) -> requests.models.Response:
        """Send DELETE request in current session"""
        response = self._session.delete(url=url, data=json.dumps(payload),
                                        headers=self._headers, verify=True)
        if response.status_code == 401 or response.status_code == 403:
            self._session.close()
            self._create_new_session()
            response = self._session.delete(url=url, data=json.dumps(payload),
                                            headers=self._headers, verify=True)
        log.debug(f"DELETE API response: {response}")
        return response

    @retry_on_connection_error(retries=3)
    def patch(self, url, payload=None) -> requests.models.Response:
        """Send PATCH request in current session"""
        response = self._session.patch(url=url, data=json.dumps(payload),
                                       headers=self._headers, verify=True)
        if response.status_code == 401 or response.status_code == 403:
            self._session.close()
            self._create_new_session()
            response = self._session.patch(url=url, data=json.dumps(payload),
                                           headers=self._headers, verify=True)
        log.debug(f"PATCH API response: {response}")
        return response
