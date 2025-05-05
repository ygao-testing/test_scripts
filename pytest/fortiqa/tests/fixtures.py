import logging
import pytest

from filelock import FileLock
from fortiqa.tests import settings
from fortiqa.libs.lw.apiv1.api_client.api_v1_client import ApiV1Client
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client
from fortiqa.libs.forticloud.forticloud_api_client import FortiCloudApiClient

log = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def api_v2_client(tmp_path_factory):
    """Return instance of the Lacework UserApi class"""
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    fn = root_tmp_dir / "v2_user_login.lock"
    with FileLock(str(fn), timeout=100):
        with APIV2Client(settings.app.customer['account_name'], settings.app.customer['lw_api_key'],
                         settings.app.customer['lw_secret']) as api_v2_client:
            return api_v2_client


@pytest.fixture(scope='session')
def login_method():
    """Get the login_method value from config.yaml"""
    return settings.app.customer.get("login_method", "magic_link")


@pytest.fixture(scope='session')
def api_v1_client(tmp_path_factory, login_method):
    """Return instance of the Lacework API V1 class"""
    customer = settings.app.customer
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    login_type = "forticloud" if login_method == "forticloud" else "v1"
    fn = root_tmp_dir / f"{login_type}_user_login.lock"
    with FileLock(str(fn), timeout=100):
        if login_method == "forticloud":
            with FortiCloudApiClient(account=customer["account_name"], fc_username=customer["user_email"],
                                     fc_password=customer["user_password"]) as api_v1_client:
                return api_v1_client
        elif login_method == "magic_link":
            with ApiV1Client(customer['account_name'], customer['user_email'],
                             customer['sub_account']) as api_v1_client:
                return api_v1_client
