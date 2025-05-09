import logging
import pytest

from filelock import FileLock
from fortiqa.tests import settings
from fortiqa.libs.lw.apiv1.api_client.api_v1_client import ApiV1Client
from fortiqa.libs.lw.apiv2.api_client.api_v2_client import APIV2Client

log = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def api_v2_client(tmp_path_factory):
    """Return instance of the Lacework UserApi class"""
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    fn = root_tmp_dir / "v2_user_login.lock"
    with FileLock(str(fn), timeout=100):
        with APIV2Client(settings.app.customer['account_name'], settings.app.customer['lw_api_key'], settings.app.customer['lw_secret']) as api_v2_client:
            return api_v2_client


@pytest.fixture(scope='session')
def api_v1_client(tmp_path_factory):
    """Return instance of the Lacework API V1 class"""
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    fn = root_tmp_dir / "v1_user_login.lock"
    with FileLock(str(fn), timeout=100):
        with ApiV1Client(settings.app.customer['account_name'], settings.app.customer['user_email'], settings.app.customer['sub_account']) as api_v1_client:
            return api_v1_client
