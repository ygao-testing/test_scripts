import pytest
import logging
# Assuming you have a RoleHelper class for Azure
from fortiqa.libs.azure.role import RoleHelper
from fortiqa.libs.helper.general_helper import select_random_from_list

logger = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def all_azure_roles(azure_account, ingestion_tag) -> list[dict]:
    """Retrieve all Azure custom roles for the subscription, optionally filtered by tags.

    This fixture uses the 'azure_account' fixture for authentication and subscription details.
    It utilizes an instance of 'RoleHelper' to fetch Azure custom roles in the specified subscription.
    If an 'ingestion_tag' is provided, custom roles for resource groups matching the tag are retrieved.
    Otherwise, all custom roles in the subscription are returned.

    Args:
        azure_account: A data class containing Azure credentials and subscription details.
        ingestion_tag (dict[str, str]): Optional tag used to filter resource groups. If provided, only
                                        custom roles in matching resource groups are retrieved.

    Returns:
        list[dict]: A list of dictionaries representing all custom roles found in the subscription
                    that match the optional 'ingestion_tag'.
    """
    logger.info(f"Finding all Azure roles in subscription: {azure_account.subscription_id}'"
                f"{', for resource groups with tags ' + str(ingestion_tag) if ingestion_tag else ''}")
    role_helper = RoleHelper(subscription_id=azure_account.subscription_id,
                             azure_credentials=azure_account.credentials)
    all_roles = role_helper.get_roles(tags=ingestion_tag)

    if all_roles:
        logger.info(f"All Azure roles for subscription {azure_account.subscription_id}"
                    f"{', for resource groups with tags ' + str(ingestion_tag) if ingestion_tag else ''}:\n{all_roles}")
    else:
        logger.info(f"There are no Azure roles for subscription: {azure_account.subscription_id}"
                    f"{', for resource groups with tags ' + str(ingestion_tag) if ingestion_tag else ''}")
    return all_roles


@pytest.fixture(scope='session')
def random_role_instance(all_azure_roles) -> dict | None:
    """Select a random Azure custom role from the provided list of role objects.

    Args:
        all_azure_roles: A list of dictionaries representing Azure custom roles.

    Returns:
        dict | None: A randomly selected custom role dictionary or None if the list is empty.
    """
    return select_random_from_list(all_azure_roles, "Azure custom roles in the subscription")
