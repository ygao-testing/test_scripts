import logging
import requests

log = logging.getLogger(__name__)


class CloudAccounts:

    def __init__(self, user_api) -> None:
        self._user_api = user_api
        self._api_url = f"{user_api.url}/CloudAccounts"

    def list_all_cloud_accounts(self) -> requests.Response:
        """
        List all Cloud Accounts
        :return: Response
        """
        log.info("list_all_cloud_accounts")
        response = self._user_api.get(url=self._api_url)
        return response

    def get_cloud_account_by_intg_guid(self, intgGuid: str):
        """Get details about a cloud account by intgGuid

        :param intgGuid: Cloud Account intgGuid
        """
        response = self._user_api.get(url=f'{self._api_url}/{intgGuid}')
        return response

    def get_cloud_accounts_by_type(self, acc_type: str):
        """Get a list of cloud accounts of the specified type

        :param type: "AwsCfg","AwsCtSqs","AwsEksAudit", etc.
        """
        response = self._user_api.get(url=f'{self._api_url}/{acc_type}')
        return response

    def create_cloud_account(self, payload: dict) -> requests.Response:
        """
        Create one cloud account
        :param payload: Cloud Account data
        :return: Response
        """
        log.info("create_cloud_accounts()")
        response = self._user_api.post(url=self._api_url, payload=payload)
        return response

    def delete_cloud_account(self, intgGuid: str) -> requests.Response:
        """
        Delete one cloud account using intgGuid
        :param intgGuid: Cloud Account intgGuid
        :return: Response
        """
        log.info(f"delete_cloud_accounts(): {intgGuid=}")
        response = self._user_api.delete(url=f"{self._api_url}/{intgGuid}")
        return response
