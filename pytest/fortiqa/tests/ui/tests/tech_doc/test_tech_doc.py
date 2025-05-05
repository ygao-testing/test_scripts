"""Technical Documentation (Help Desk) tests"""

import pytest
import os

link_names = [
    "Integrate Your AWS Account with Your Lacework Account",
    "Integrate Your Azure Account with Your Lacework Account",
    "Integrate Your GCP Account with Your Lacework Account",
    "Terraform for Lacework Overview",
    "Lacework doc"
]


@pytest.mark.skipif(os.environ.get("GITHUB_ACTIONS"), reason="Account not ready for SGMTEST")
@pytest.mark.parametrize("link_name", link_names)
def test_tech_doc_onboarding_page(ui, link_name):
    """
    Technical Documentation on the Onboarding pages
    1. Open the "Onboarding page".
    2. Open the Tech Doc page and verify.
    """
    ui.settings_onboarding.open_onboarding("Configure cloud accounts")
    ui.settings_onboarding.open_tech_doc_and_verify(link_name)
