import logging
from typing import Any
from azure.identity import ClientSecretCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import ResourceManagementClient

logger = logging.getLogger(__name__)


class RoleHelper:
    """
    A helper class to interact with Azure custom roles using the AuthorizationManagementClient.
    It can filter roles by resource group, tags, or retrieve all roles in the subscription.

    Attributes:
        client (AuthorizationManagementClient): Azure Authorization Management Client for role operations.
        resource_client (ResourceManagementClient): Azure Resource Management Client for resource group operations.
    """

    def __init__(self, subscription_id: str, azure_credentials: dict):
        """
        Initialize the RoleHelper with Azure AuthorizationManagementClient.

        :param subscription_id: Azure subscription ID.
        :param azure_credentials: Dictionary containing Azure credentials:
                                  - tenant_id (str): Azure tenant ID.
                                  - client_id (str): Azure client ID.
                                  - client_secret (str): Azure client secret.
        """
        self.credentials = ClientSecretCredential(
            tenant_id=azure_credentials["tenant_id"],
            client_id=azure_credentials["client_id"],
            client_secret=azure_credentials["client_secret"],
        )
        self.subscription_id = subscription_id
        self.client = AuthorizationManagementClient(self.credentials, self.subscription_id)
        self.resource_client = ResourceManagementClient(self.credentials, self.subscription_id)

    def get_roles(self, resource_group: str | None = None, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Retrieve all custom roles within the Azure subscription, filtered by resource group and/or tags.

        This method supports flexible querying of custom roles:
        - If a resource group is specified, it retrieves roles only for that group.
        - If tags are specified without a resource group, it identifies resource groups matching the tags
          and retrieves roles for them.
        - If neither resource group nor tags are provided, it retrieves all custom roles in the subscription.

        :param resource_group: Optional name of the resource group to filter roles. Defaults to None.
        :param tags: Optional dictionary of tags to filter resource groups. Keys are tag names, and values are tag values.
                     Example: {"Environment": "Test", "Owner": "QA"}.
        :return: A list of dictionaries containing role details. Each dictionary represents a role and includes
                 properties such as name, type, and scope.

        Example Usage:
        ---------------
        1. Retrieve roles from a specific resource group:
            roles = role_helper.get_roles(resource_group="test-resource-group")

        2. Retrieve roles for resource groups with specific tags:
            roles = role_helper.get_roles(tags={"Environment": "Test", "Owner": "QA"})

        3. Retrieve all roles in the subscription:
            roles = role_helper.get_roles()
        """
        roles = []

        if resource_group:
            # Retrieve roles for a specific resource group
            logger.info(f"Retrieving roles for resource group: {resource_group}")
            scope = f"/subscriptions/{self.subscription_id}/resourceGroups/{resource_group}"
            roles_list = self.client.role_definitions.list(scope, filter="type eq 'CustomRole'")
            roles.extend([role.as_dict() for role in roles_list])
            logger.info(f"Retrieved {len(roles)} roles for resource group: {resource_group}")

        elif tags:
            # Retrieve resource groups matching the tags
            logger.info(f"Retrieving resource groups with tags: {tags}")
            resource_groups = self.resource_client.resource_groups.list()
            tagged_resource_groups = [
                rg.name for rg in resource_groups
                if rg.tags and all(rg.tags.get(key) == value for key, value in tags.items())
            ]

            if tagged_resource_groups:
                logger.info(f"Found resource groups with matching tags: {tagged_resource_groups}")
                # Retrieve roles for each resource group
                for rg_name in tagged_resource_groups:
                    logger.info(f"Retrieving roles for resource group: {rg_name}")
                    scope = f"/subscriptions/{self.subscription_id}/resourceGroups/{rg_name}"
                    roles_list = self.client.role_definitions.list(scope, filter="type eq 'CustomRole'")
                    roles.extend([role.as_dict() for role in roles_list])
                logger.info(f"Retrieved {len(roles)} roles for resource groups with matching tags.")
            else:
                logger.warning(f"No resource groups found with tags: {tags}")

        else:
            # Retrieve all roles in the subscription
            logger.info("No resource group or tags provided. Retrieving all roles in the subscription.")
            scope = f"/subscriptions/{self.subscription_id}"
            roles_list = self.client.role_definitions.list(scope, filter="Type eq 'CustomRole'")
            roles.extend([role.as_dict() for role in roles_list])
            logger.info(f"Retrieved {len(roles)} roles from the subscription.")

        return roles
