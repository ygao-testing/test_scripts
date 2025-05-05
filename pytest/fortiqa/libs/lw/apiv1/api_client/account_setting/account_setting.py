import logging
import requests
from datetime import datetime, timedelta, timezone

from fortiqa.libs.lw.apiv1.api_client.api_v1_client import ApiV1Client
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response

logger = logging.getLogger(__name__)


class AccountSettingV1:
    """A class to interact with the account settings API and manage collection times."""

    def __init__(self, api_v1_client: ApiV1Client) -> None:
        """Initializes the AccountSetting class.

        Args:
            api_v1_client (api_v1_client): An instance of the API v1 client for sending requests.
        """
        self._user_api = api_v1_client
        self._api_url = f"{api_v1_client.url}/accounts/settings"

    def get_account_setting(self) -> requests.Response:
        """Retrieves the account settings from the API.

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.info("get account setting")
        response = self._user_api.get(url=self._api_url)
        logger.debug(f"account setting response: {response.text}")
        return response

    def get_daily_collection_start_time(self) -> int:
        """Retrieves the start time for the daily collection from the account settings.

        Returns:
            int: The hour of the daily collection start time.

        Raises:
            Exception: If the status code of the response is not 200 or if the response format is invalid.
        """
        account_setting_response = self.get_account_setting()
        if account_setting_response.status_code != 200:
            raise Exception(
                f"Failed to retrieve account settings. Status code: {account_setting_response.status_code}, "
                f"Response: {account_setting_response.text}"
             )
        account_setting_json = check_and_return_json_from_response(account_setting_response)
        start_time = account_setting_json['data'][0]['assetInventoryCollection']['startTime']
        logger.debug(f"Daily collection start time: {start_time}")
        return start_time

    def get_next_collection_time(self) -> datetime:
        """Calculates the next collection time based on the current UTC time and the start time retrieved.

        Returns:
            datetime: The next collection time in UTC.
        """
        start_time_hour = self.get_daily_collection_start_time()
        current_utc_time = datetime.now(timezone.utc)
        if start_time_hour <= current_utc_time.hour:
            next_collection_time = current_utc_time + timedelta(days=1)
            next_collection_time = next_collection_time.replace(hour=start_time_hour, minute=0, second=0, microsecond=0)
        else:
            next_collection_time = current_utc_time.replace(hour=start_time_hour, minute=0, second=0, microsecond=0)
        logger.debug(f'Next collection time: {next_collection_time.strftime("%Y-%m-%dT%H:%M:%SZ")}')
        return next_collection_time
