import pytest
import logging
import requests
from fortiqa.tests.ui.utils.lacework_webcrawl import LaceworkPage
from fortiqa.tests import settings

log = logging.getLogger(__name__)

urls = [
    '/ui/investigation/cloud/KubernetesDashboard',
    '/ui/investigation/identities/overview',
    '/ui/investigation/reports',
    '/ui/investigation/agentless/AgentlessDashboard/accounts',
    '/ui/investigation/settings/channels/rules/alert/new',
    '/ui/investigation/settings/channels/rules/dataexport/new',
    '/ui/investigation/settings/channels/rules/report/new',
    '/ui/investigation/settings/identityproviders',
    '/ui/investigation/settings/jiravulnintegration',
    '/ui/investigation/settings/riskscores',
    '/ui/investigation/settings/general',
    '/ui/investigation/settings/subscription',
    '/ui/investigation/settings/profile',
    '/ui/welcome/workflow/cloudaccounts',
    '/ui/welcome/workflow/agents',
    '/ui/welcome/workflow/alertchannels',
    '/ui/welcome/workflow/users',
    '/ui/welcome/workflow/containerregistries'
]


@pytest.mark.sanity
def test_documentation_links(sb):
    """
    Testcase verify lacework documentation links
    1. Login Lacework website
    2. Retrieve documentation links
    3. Verify no Lacework reference in documentation links
    4. Verify Fortinet documentation links are valid
    :param sb: Seleniumbase baseclass object
    :return None
    """
    log.info("1. Login Lacework website")
    url = "https://" + settings.app.customer["account_name"] + ".lacework.net/"
    LaceworkPage(sb).open_page(user_email=settings.app.customer['user_email'], url=url)

    log.info("2. Retrieve documentation links")
    fortinet_documentation_links = []
    lacework_documentation_links = []
    for _url in urls:
        _url = url + _url
        _fortinet_documentation_links, _lacework_documentation_links = LaceworkPage(sb).verify_documentation_links(
            url=_url)
        fortinet_documentation_links.extend(_fortinet_documentation_links)
        lacework_documentation_links.extend(_lacework_documentation_links)

    log.info("3. Verify no Lacework reference in documentation links")
    assert len(
        lacework_documentation_links) == 0, f"There are instances of Lacework reference in documentation links: {lacework_documentation_links}"

    log.info("4. Verify Fortinet documentation links are valid")
    for documentation_link in list(set(fortinet_documentation_links)):
        response = requests.session().get(documentation_link)
        assert response.status_code == 200, f"Fortinet documentation link {documentation_link} could not be opened"
