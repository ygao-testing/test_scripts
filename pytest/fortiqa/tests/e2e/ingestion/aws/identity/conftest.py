import logging
import pytest
from fortiqa.libs.lw.apiv1.api_client.identity.identity import IdentityV1
logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def identity_v1_client(api_v1_client):
    """Provides an instance of IdentityV1 to interact with the Lacework Identity API.
    Given:
        - A  Lacework API  V1 client.
    Returns:
        - An IdentityV1 instance that can be used to make API calls.
    """
    return IdentityV1(api_v1_client)


@pytest.fixture(scope="session")
def all_aws_iam_groups_deployed_for_identity(e2e_aws_resources):
    """
    Fixture to retrieve all AWS IAM group names deployed for identity via Terraform.

    Given:
        - Terraform module output for iam_group_identity.

    Returns:
        - A list of IAM group names deployed in AWS.
    """
    iam_group_identity_module = e2e_aws_resources["iam_group_identity"]["tf"]
    output = iam_group_identity_module.output()
    iam_group_names = output.get("iam_group_names", [])
    if iam_group_names:
        logger.info(f"All IAM groups deployed for identity:\n{iam_group_names}")
    else:
        logger.info("No IAM groups deployed for identity were found in the Terraform output.")
    return iam_group_names
