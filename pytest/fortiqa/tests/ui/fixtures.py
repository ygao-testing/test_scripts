"""GUI and API Fixtures"""
import logging
import pytest
import requests
import json
import time
import os

from fortiqa.libs.lw.apiv1.api_client.api_v1_client import get_latest_email
from fortiqa.tests import settings
from fortiqa.tests.ui.utils.ui_app import UiApp
from fortiqa.tests.ui.utils.work_with_files import Files

from datetime import datetime, timezone

ui_app = None
info = logging.getLogger(__name__).info
log = logging.getLogger(__name__)


@pytest.fixture
def ui(ui_session, get_login_url):
    """
    Before each test, verify the browser is valid, otherwise, open a new browser.
    After each test, verify no popup error messages (and close them if the messages are present)
    """
    global ui_app
    if not ui_app.is_valid():
        ui_app = UiApp(get_login_url)

    ui_app.session.login(get_login_url)

    main_window_handle = ui_app.driver.current_window_handle
    ui_app.leave_only_one_window(main_window_handle)

    yield ui_app
    ui_app.leave_only_one_window(main_window_handle)
    ui_app.driver.implicitly_wait(settings.ui.default_implicit_wait)


@pytest.fixture(scope="session")
def ui_session(get_login_url):
    """Once per session, open the browser and login. Close the browser in the end."""
    global ui_app
    ui_app = UiApp(get_login_url)
    ui_app.session.login(get_login_url)
    yield
    ui_app.driver.quit()


@pytest.fixture(scope="session")
def get_login_url():
    """
    Fixture to get Login URL from Email
    1. Verify session cookies if exists
    2. If no valid cookies exist, proceed with email-based login
    3. Save cookies for future use
    """
    account = settings.app.customer['account_name']
    account_name = account.split(".")[0]
    email = settings.app.customer['user_email']
    sub_account = settings.app.customer['sub_account']
    session = requests.Session()
    url = f"https://{account}.lacework.net/api/v1"
    headers = {
        'X-LW-UAKS': settings.app.customer['lw_secret'],
        'Content-type': 'application/json'
    }
    payload = json.dumps({
        "keyId": settings.app.customer['lw_api_key'],
        'expiryTime': 36000
    })
    response = session.post(f"{url}/access/tokens", headers=headers, data=payload)
    access_token = response.json()['data'][0]['token']
    headers['Authorization'] = f"Bearer {access_token}"

    # First try to use existing cookies
    if os.path.exists("cookies.json"):
        with open("cookies.json", "r") as cookie_file:
            data = json.load(cookie_file)
        sid = data.get("SID")
        xsrf_token = data.get("XSRF-TOKEN")
        if sid and xsrf_token:
            # Try to use existing cookies
            os.environ["VALID_COOKIES"] = "True"
            headers['SID'] = sid
            headers['X-Xsrf-Token'] = xsrf_token
            headers['Accountname'] = sub_account if sub_account else account_name
            try:
                # Make a test API call to verify cookie validity
                test_response = session.get(f"{url}/profile/info", headers=headers)
                if test_response.status_code == 200:
                    log.info("Successfully reused existing cookies from cookies.json")
                    # Should be able to open homepage without SID in url
                    portal_url = f"https://{account}.lacework.net/ui/investigation/Dashboard"
                    return portal_url
                else:
                    log.info("Existing cookies are invalid, proceeding with email login.")
                    os.environ["VALID_COOKIES"] = "False"
            except Exception as e:
                log.info(f"Failed to validate existing cookies: {str(e)}")
    else:
        log.info("No existing cookies, proceeding with email login.")

    # If no valid cookies exist, proceed with email-based login
    current_time_utc = datetime.now(timezone.utc)
    get_auth_id_response = session.get(url=f"{url}/accounts/acnt_name/{account_name}/authConfig", headers=headers)
    auth_id = get_auth_id_response.json()['data'][0]['CUST_AUTH_CFG']['AUTH_SETTINGS_CONFIG']['INTG_GUID']
    login_payload = json.dumps(dict(
        email=email,
        account=account_name,
        authIntgGuid=auth_id
    ))
    time.sleep(60)  # Wait at least 1 minute to make sure using the latest email link
    login_response = session.post(url=f"{url}/login/link", data=login_payload, headers=headers)
    time.sleep(15)  # Wait for sending email
    assert login_response.status_code == 200, "Login failed"
    url_sid = get_latest_email(account_name, sub_account, current_time_utc)

    portal_url = f"https://{account}.lacework.net/ui/home?SID={url_sid}"
    if sub_account:
        portal_url = f"{portal_url}&accountName={sub_account}"

    # Save cookies for future use
    login_cookie = session.get(portal_url, headers=headers).cookies
    log.info(f"Get login cookies using SID: {login_cookie}")
    xsrf_token = login_cookie.get('XSRF-TOKEN', None)
    if xsrf_token:
        log.info("New SID is useable, store the cookies inside a json file for future use")
        os.environ["VALID_COOKIES"] = "True"
        with open("cookies.json", "w") as cookie_file:
            json.dump(login_cookie.get_dict(), cookie_file)

    return portal_url


@pytest.fixture
def delete_files(ui, request):
    """
    Delete all the files name starting with <prefix> end with <suffix>
    If param not provided, will delete all .csv files.
    """
    yield
    if not os.environ.get("GITHUB_ACTIONS"):
        info('Delete all the files name starting with <prefix> end with <suffix>')
        file_name = getattr(request, "param", {"prefix": "", "suffix": "csv"})
        Files().delete_file(file_name["prefix"], file_name["suffix"], driver=ui.driver)
