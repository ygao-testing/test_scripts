import pytest
import logging
from fortiqa.libs.azure.vm import VMHelper  # Assuming you have a VMHelper class for Azure
from fortiqa.libs.helper.general_helper import select_random_from_list

logger = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def all_azure_vms(azure_account, ingestion_tag) -> list[dict]:
    """
    Retrieve all Azure VMs for the subscription, optionally filtered by tags.

    This fixture uses the 'azure_account' fixture for authentication and subscription details.
    It utilizes an instance of 'VMHelper' to fetch Azure VMs in the specified subscription.
    If an 'ingestion_tag' is provided, only VMs matching the tag are retrieved. Otherwise,
    all VMs in the subscription are returned.

    Args:
        azure_account: A data class containing Azure credentials and subscription details.
        ingestion_tag (dict[str, str]): Optional tag used to filter resources. If provided, only
                                        VMs matching the tag are retrieved.

    Returns:
        list[dict]: A list of dictionaries representing all VMs found in the subscription
                    that match the optional 'ingestion_tag'.
    """
    logger.info(f"Finding all Azure VMs in subscription: {azure_account.subscription_id}'"
                f"{', with tags ' + str(ingestion_tag) if ingestion_tag else ''}")
    vm_helper = VMHelper(subscription_id=azure_account.subscription_id, azure_credentials=azure_account.credentials)
    all_vms = vm_helper.get_all_vms_raw(tags=ingestion_tag)

    if all_vms:
        logger.info(f"All Azure VMs for subscription {azure_account.subscription_id}"
                    f"{', with tags ' + str(ingestion_tag) if ingestion_tag else ''}:\n{all_vms}")
    else:
        logger.info(f"There are no Azure VMs for subscription: {azure_account.subscription_id}"
                    f"{', with tags ' + str(ingestion_tag) if ingestion_tag else ''}")
    return all_vms


@pytest.fixture(scope='session')
def random_vm_instance(all_azure_vms) -> dict | None:
    """
    Select a random Azure VM from the provided list of VM objects.

    Args:
        all_azure_vms: A list of dictionaries representing Azure VMs.

    Returns:
        dict | None: A randomly selected VM dictionary or None if the list is empty.
    """
    return select_random_from_list(all_azure_vms, "Azure VMs in the subscription")
