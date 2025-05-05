import json
import logging

import pytest

from fortiqa.libs.terraform.tf_parser import TFParser
from fortiqa.libs.lw.apiv2.helpers.cloud_account_helper import CloudAccountHelper

logger = logging.getLogger(__name__)


@pytest.mark.parametrize('deploy_lacework_tf_module', [
    'aws_config',
    'aws_cloudtrail',
], indirect=True)
def test_aws_integrations(api_v2_client, deploy_lacework_tf_module):
    """Verify cloud account integrations created using lacework TF provider are returned by LW API.

    Given: Applied TF module that creates cloud account integration.
    When: Listing existing cloud accounts using LW API.
    Then: Cloud account integrations deployed by terraform should be found in the list returned by API.

    Args:
        api_v2_client: API V2 client for interacting with the Lacework
        deploy_lacework_tf_module: deploys/destroys given TF module.
    """
    cloud_accounts = TFParser(
        working_dirs=[deploy_lacework_tf_module.tfdir]
    ).get_lw_cloud_accounts()
    resp = CloudAccountHelper(api_v2_client).get_all_cloud_accounts()
    accounts_from_api = json.loads(resp.text)['data']
    not_found = []
    for account in cloud_accounts:
        found = False
        for acc in accounts_from_api:
            if account['name'] == acc['name'] and \
               account['type'] == acc['type'] and \
               account['intg_guid'] == acc['intgGuid']:
                found = True
        if not found:
            not_found.append(account)
    assert len(not_found) == 0, f'Accounts {not_found} were not found in API response {accounts_from_api}' # noqa : E713
