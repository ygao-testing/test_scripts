import logging

from fortiqa.libs.azure.azurehelper import AzureHelper

log = logging.getLogger(__name__)


class SubscriptionHelper(AzureHelper):
    def __init__(self, subscription_id: str, azure_credentials: dict):
        """
        Initialize the SubscriptionHelper with Azure StorageManagementClient.

        :param subscription_id: Azure subscription ID.
        :param azure_credentials: Dictionary containing Azure credentials:
                                - tenant_id (str): Azure tenant ID.
                                - client_id (str): Azure client ID.
                                - client_secret (str): Azure client secret.
        """
        super().__init__("subscription", subscription_id, azure_credentials)

    def list_all_subscriptions(self):
        """Function to list all subscriptions inside Azure"""
        log.info('list_all_subscriptions()')
        resp = self.client.subscriptions.list()
        return resp

    def fetch_current_subscription_name(self):
        """Function to fetch current subscription's name by ID"""
        log.info('list_all_subscriptions()')
        all_subscriptions = self.list_all_subscriptions()
        for subscription in all_subscriptions:
            if subscription.subscription_id == self.subscription_id:
                return subscription.display_name
        raise Exception(f"Not found any subscription has ID={self.subscription_id}")
