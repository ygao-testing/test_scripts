import logging
import time

from fortiqa.libs.azure.azurehelper import AzureHelper

log = logging.getLogger(__name__)


class StorageManagementHelper(AzureHelper):
    def __init__(self, subscription_id: str, azure_credentials: dict):
        """
        Initialize the StorageManagementHelper with Azure StorageManagementClient.

        :param subscription_id: Azure subscription ID.
        :param azure_credentials: Dictionary containing Azure credentials:
                                - tenant_id (str): Azure tenant ID.
                                - client_id (str): Azure client ID.
                                - client_secret (str): Azure client secret.
        """
        super().__init__("storage", subscription_id, azure_credentials)

    def delete_storage_account(self, storage_account_name: str, resource_group_name: str):
        """
        Function to delete storage account inside the customer resource group

        :param storage_account_name: Name of the storage account inside the resource group
        :param resource_group_name: Name of the resource group in which the storage account exists
        """
        log.info('delete_storage_account()')
        resp = self.client.storage_accounts.delete(
            resource_group_name,
            storage_account_name
        )
        return resp

    def list_storage_account_inside_resource_group(self, resource_group_name: str):
        """
        Function to list all storage accounts inside the customer resource group

        :param resource_group_name: Name of the resource group
        """
        log.info(f'list_storage_account({resource_group_name=})')
        resp = self.client.storage_accounts.list_by_resource_group(
            resource_group_name
        )
        return resp

    def list_storage_accounts(self):
        """Function to list all storage accounts inside Azure Subscription"""
        log.info('list_storage_accounts()')
        resp = self.client.storage_accounts.list()
        return resp

    def wait_until_storage_account_created(self, storage_account_name: str, timeout: int = 1200):
        """
        Function to check whether a storage account is created inside Azure within a time limit

        :param storage_account_name: The storage account to check
        :param timeout: The maximum time to wait until the expected storage account to be created
        :raises: `TimeoutError` if there is no expected storage account created after timeout
        """
        log.info(f"Finding storage_account {storage_account_name} in Azure")
        found_account = False
        start_time = time.monotonic()
        time_passed = 0
        while time_passed < timeout and not found_account:
            time_passed = int(time.monotonic() - start_time)
            all_storage_accounts = self.list_storage_accounts()
            found_account = any(storage_account.name == storage_account_name for storage_account in all_storage_accounts)
            if not found_account:
                time.sleep(60)
        if not found_account:
            log.debug(f"Expected Account: {storage_account_name} created after {time_passed} sec")
            raise TimeoutError(f"There is no storage account {storage_account_name} inside Azure after {time_passed} sec")
