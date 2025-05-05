from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient


class AzureHelper:
    """
    A helper class to initialize Azure service clients dynamically based on the specified service name.

    Attributes:
        credentials (ClientSecretCredential): Azure credentials for authentication.
        subscription_id (str): Azure subscription ID.
        client (object): Azure service client for the specified service.
    """

    def __init__(self, service_name: str, subscription_id: str, azure_credentials: dict):
        """
        Initialize the Azure client for the specified service.

        :param service_name: Name of the Azure service ('compute', 'storage', 'network', etc.).
        :param subscription_id: Azure subscription ID.
        :param azure_credentials: Dictionary containing Azure credentials:
                                  - tenant_id (str): Azure tenant ID.
                                  - client_id (str): Azure client ID.
                                  - client_secret (str): Azure client secret.
        :raises ValueError: If an unsupported service name is provided.
        """
        self.credentials = ClientSecretCredential(
            tenant_id=azure_credentials['tenant_id'],
            client_id=azure_credentials['client_id'],
            client_secret=azure_credentials['client_secret']
        )
        self.subscription_id = subscription_id

        # Dynamically initialize the appropriate client
        if service_name == "compute":
            self.client = ComputeManagementClient(
                self.credentials, self.subscription_id)
        elif service_name == "storage":
            self.client = StorageManagementClient(
                self.credentials, self.subscription_id)
        elif service_name == "network":
            self.client = NetworkManagementClient(
                self.credentials, self.subscription_id)
        elif service_name == "subscription":
            self.client = SubscriptionClient(
                self.credentials
            )
        else:
            raise ValueError(f"Unsupported service: {service_name}")
