import logging
from typing import Any
from azure.mgmt.resource import ResourceManagementClient
from fortiqa.libs.azure.azurehelper import AzureHelper

logger = logging.getLogger(__name__)


class VMHelper(AzureHelper):
    """
    A helper class for managing Azure Virtual Machines (VMs) using the ComputeManagementClient.
    Inherits from AzureHelper to dynamically initialize the compute client.

    Attributes:
        client (ComputeManagementClient): Azure Compute Management Client for VM operations.
        resource_client (ResourceManagementClient): Azure Resource Management Client for resource operations.
    """

    def __init__(self, subscription_id: str, azure_credentials: dict):
        """
        Initialize the VMHelper with Azure ComputeManagementClient.

        :param subscription_id: Azure subscription ID.
        :param azure_credentials: Dictionary containing Azure credentials:
                                  - tenant_id (str): Azure tenant ID.
                                  - client_id (str): Azure client ID.
                                  - client_secret (str): Azure client secret.
        """
        super().__init__("compute", subscription_id, azure_credentials)
        self.resource_client = ResourceManagementClient(
            self.credentials, self.subscription_id)

    def get_all_vms_raw(self, resource_group: str | None = None, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """
        Retrieve all Virtual Machines (VMs) in the subscription, filtered by resource group and/or tags.

        This method supports flexible querying of VMs:
        - If a resource group is specified, it retrieves VMs only from that group.
        - If tags are specified without a resource group, it first identifies resource groups matching
        those tags and retrieves VMs from them. If no resource groups match, it retrieves all VMs
        across the subscription with the specified tags.
        - If neither resource group nor tags are provided, it retrieves all VMs in the subscription.

        :param resource_group: Optional name of the resource group to filter VMs. Defaults to None.
        :param tags: Optional dictionary of tags to filter VMs. Keys are tag names, and values are tag values.
                    Example: {"Environment": "Test", "Owner": "QA"}
        :return: A list of dictionaries containing VM details. Each dictionary represents a VM and includes
                its properties such as name, tags, location, and provisioning state.

        Example Usage:
        ---------------
        1. Retrieve VMs from a specific resource group:
            vms = vm_helper.get_all_vms_raw(resource_group="test-resource-group")

        2. Retrieve VMs with specific tags:
            vms = vm_helper.get_all_vms_raw(tags={"Environment": "Test", "Owner": "QA"})

        3. Retrieve all VMs in the subscription:
            vms = vm_helper.get_all_vms_raw()
        """
        vms = []

        if resource_group:
            # Log resource group-based query
            logger.info(f"Querying all VMs for resource group: {resource_group}")
            vm_list = self.client.virtual_machines.list(resource_group)
            vms.extend([vm.as_dict() for vm in vm_list])
            logger.info(f"Retrieved {len(vms)} VMs from resource group '{resource_group}'.")

        elif tags:
            # Log retrieval of resource groups by tags
            logger.info(f"Retrieving resource groups with tags: {tags}")
            resource_groups = self.resource_client.resource_groups.list()
            tagged_resource_groups = [
                rg.name for rg in resource_groups
                if rg.tags and all(rg.tags.get(key) == value for key, value in tags.items())
            ]

            if tagged_resource_groups:
                logger.info(f"Found resource groups with matching tags: {tagged_resource_groups}")
                # Retrieve VMs from these resource groups
                for rg_name in tagged_resource_groups:
                    logger.info(f"Querying VMs in resource group: {rg_name}")
                    vm_list = self.client.virtual_machines.list(rg_name)
                    vms.extend([vm.as_dict() for vm in vm_list])
                logger.info(
                    f"Retrieved {len(vms)} VMs from resource groups with matching tags.")
            else:
                # If no matching resource groups are found
                logger.info(
                    f"No resource groups found with tags: {tags}. Retrieving VMs with matching tags across subscription.")
                vm_list = self.client.virtual_machines.list_all()
                for vm in vm_list:
                    if vm.tags and all(vm.tags.get(key) == value for key, value in tags.items()):
                        vms.append(vm.as_dict())
                logger.info(f"Retrieved {len(vms)} VMs with tags {tags} across the subscription.")

        else:
            # Log retrieval of all VMs in the subscription
            logger.info(
                "No resource group or tags provided. Retrieving all VMs in the subscription.")
            vm_list = self.client.virtual_machines.list_all()
            vms.extend([vm.as_dict() for vm in vm_list])
            logger.info(f"Retrieved {len(vms)} VMs from the subscription.")

        return vms
