import json
import logging
import os
import requests
import imaplib
import email
import re
import time
from functools import wraps
from requests.exceptions import ConnectionError
from fortiqa.tests import settings
from email.header import decode_header
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timezone

log = logging.getLogger(__name__)

disable_warnings(InsecureRequestWarning)


def retry_on_connection_error(retries=3):  # Decorator factory, takes in `retries`
    """Decorator to retry a method on ConnectionError, reinitializing the session .

    This decorator wraps a function and retries the specified number of times after an initial attempt.
    Each retry applies exponential backoff and session reinitialization with a login step to re-authenticate.

    Args:
        retries (int): The number of retries after the initial attempt. Default is 3.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except ConnectionError as e:
                log.error(f"ConnectionError on initial attempt: {e}")
                log.info(f"Beginning retries with up to {retries} attempts...")

            # Retry attempts if initial attempt fails
            for attempt in range(1, retries + 2):
                try:
                    log.info(f"Retry attempt {attempt}/{retries}")
                    return func(self, *args, **kwargs)
                except ConnectionError as e:
                    log.error(f"ConnectionError on retry attempt {attempt}/{retries}: {e}")

                    # Only retry if there are more attempts left
                    if attempt < retries + 1:
                        self._session.close()
                        backoff_time = 2 ** attempt
                        log.info(f"Applying backoff, waiting {backoff_time} seconds before retrying...")
                        time.sleep(backoff_time)
                        log.info("Reinitializing session and re-authenticating.")
                        self._create_new_session()
                        self.login()
                    else:
                        # Last attempt has failed; raise the error
                        raise ConnectionError(f"Failed to connect after {retries + 1} total attempts: {e}")

        return wrapper

    return decorator


def get_latest_email(account_name: str, sub_account: str, test_start_datetime: datetime):
    """
    This function connects to Yahoo's IMAP server to fetch the latest email with
    "Lacework FortiCNAPP - login information" subject, extracts SID URLs,
    and deletes the email afterward.

    Args:
        account_name: Account Name, e.g. fortiqa.
        test_start_datetime: The datetime before calling this function.

    Returns:
        str: The SID value extracted from the email or an empty string if no email is found.
    """
    mail = imaplib.IMAP4_SSL("imap.mail.yahoo.com")
    mail.login(settings.app.customer['user_email'], settings.app.customer['user_email_password'])
    folders_to_check = ['inbox', 'Archive']  # I added a filter to move all login information emails to Archive for fcsqagen2@yahoo.com only.
    sid_values = None
    for folder in folders_to_check:
        mail.select(folder)
        _, messages_account = mail.search(None, f'(SUBJECT "Lacework FortiCNAPP - login information ({account_name})")')
        _, messages_sub_account = mail.search(None, f'(SUBJECT "Lacework FortiCNAPP - login information ({sub_account})")')
        messages_account = messages_account[0].split()
        messages_sub_account = messages_sub_account[0].split()
        if not messages_account and not messages_sub_account:
            log.info(f"Not receiving any Lacework confirmation email under {folder}")
        else:
            messages = messages_sub_account if messages_sub_account else messages_account
            log.info(f"Received Lacework confirmation email under {folder}")
            latest_email_id = messages[-1]
            _, msg_data = mail.fetch(latest_email_id, "(RFC822)")

            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding if encoding else "utf-8")
                    body = msg.get_payload(decode=True).decode()  # type: ignore
                    sid_urls = re.findall(r'https://[^\s]*SID[^\s]*(?<!")', body)
                    sid_values = [re.search(r'SID=([^&\s]+)', url).group(1) for url in sid_urls if re.search(r'SID=([^&\s]+)', url)]  # type: ignore
                    if sid_urls:
                        date_header = msg["Date"]
                        email_date = email.utils.parsedate_to_datetime(date_header)
                        email_date_utc = email_date.astimezone(timezone.utc)
                        log.info(f"Found login URLs: {sid_urls}, it was sent on {email_date_utc} UTC time")
                        if email_date_utc < test_start_datetime:
                            # Email was sent before the Test start time
                            log.debug(f"Login process started on {test_start_datetime} UTC, but did not find login confirmation email after that")
                            sid_values = None
            mail.store(latest_email_id, '+FLAGS', '\\Deleted')
            mail.expunge()
            mail.close()
            if sid_values:
                mail.logout()
                return sid_values[0]
    mail.logout()
    if not sid_values:
        log.debug("Not receiving any Lacework confirmation email under both Inbox and Archive folders")
    return ""


class ApiV1Client(object):

    def __init__(self, account: str, email_address: str, subaccount: str = "") -> None:
        self.base_url = f"https://{account}.lacework.net"    # noqa: E231
        self.url = f"https://{account}.lacework.net/api/v1"  # noqa: E231
        self.account = account
        self.account_name = account.split(".")[0]
        self.sub_account = subaccount
        self.user_secret = settings.app.customer['lw_secret']
        self.user_keyid = settings.app.customer['lw_api_key']
        self.email_address = email_address
        self._create_new_session()
        self.login()

    def __enter__(self):
        return self

    def __exit__(self, exception_type,
                 exception_value, exception_traceback) -> None:
        self._session.close()

    def _create_new_session(self):
        self._session = requests.session()
        self._headers = {
            'X-LW-UAKS': self.user_secret,
            'Content-type': 'application/json'
        }
        payload = json.dumps({
            "keyId": self.user_keyid,
            'expiryTime': 36000
        })
        response = self._session.post(f"{self.url}/access/tokens", headers=self._headers, data=payload)
        self._access_token = response.json()['data'][0]['token']
        self._headers['Authorization'] = f"Bearer {self._access_token}"
        self._cookies = None

    def login(self, login: bool = True):
        """Simulate Customer login process

        First tries to use existing cookies from cookies.json.
        If cookies are invalid or don't exist, falls back to email-based login.
        """
        # First try to use existing cookies
        if os.path.exists("cookies.json"):
            with open("cookies.json", "r") as cookie_file:
                data = json.load(cookie_file)
            sid = data.get("SID")
            xsrf_token = data.get("XSRF-TOKEN")
            if sid and xsrf_token:
                # Try to use existing cookies
                self._headers['SID'] = sid
                self._headers['X-Xsrf-Token'] = xsrf_token
                self._headers['Accountname'] = self.sub_account if self.sub_account else self.account_name
                try:
                    # Make a test API call to verify cookie validity
                    test_response = self._session.get(f"{self.url}/profile/info", headers=self._headers)
                    if test_response.status_code == 200:
                        log.info("Successfully reused existing cookies from cookies.json")
                        self._cookies = requests.cookies.cookiejar_from_dict(data)
                        return
                    log.info("Existing cookies are invalid, proceeding with email login")
                except Exception as e:
                    log.info(f"Failed to validate existing cookies: {str(e)}")

        # If no valid cookies exist, proceed with email-based login
        current_time_utc = datetime.now(timezone.utc)
        get_auth_id_response = self._session.get(url=f"{self.url}/accounts/acnt_name/{self.account_name}/authConfig", headers=self._headers)
        auth_id = get_auth_id_response.json()['data'][0]['CUST_AUTH_CFG']['AUTH_SETTINGS_CONFIG']['INTG_GUID']
        login_payload = json.dumps(dict(
            email=self.email_address,
            account=self.account_name,
            authIntgGuid=auth_id
        ))
        time.sleep(60)
        login_response = self._session.post(url=f"{self.url}/login/link", data=login_payload, headers=self._headers)
        assert login_response.status_code == 200, "Login failed"
        self._headers['Accountname'] = self.account_name
        log_in = False
        retry = 5
        while not log_in and retry > 0:
            time.sleep(30)
            sid = get_latest_email(account_name=self.account_name, sub_account=self.sub_account, test_start_datetime=current_time_utc)
            xsrf_token = None
            if not sid:
                log.debug("Failed to get confirmation email inside Yahoo account")
                if os.path.exists("cookies.json"):
                    with open("cookies.json", "r") as cookie_file:
                        data = json.load(cookie_file)
                    sid = data.get("SID")
                    self._cookies = requests.cookies.cookiejar_from_dict(data)
            else:
                log.debug("Successfully received the email, need to check if it's useable")
                portal_url = f"{self.base_url}/ui/home?SID={sid}"
                if self.sub_account:
                    portal_url = f"{portal_url}&accountName={self.sub_account}"
                    self._headers['Accountname'] = self.sub_account
                login_cookie = self._session.get(portal_url, headers=self._headers).cookies
                log.info(f"Get login cookies using SID: {login_cookie}")
                xsrf_token = login_cookie.get('XSRF-TOKEN', None)
                if not xsrf_token:
                    log.info("Failed to use the SID to login, fetch stored cookies")
                    if os.path.exists("cookies.json"):
                        with open("cookies.json", "r") as cookie_file:
                            data = json.load(cookie_file)
                        xsrf_token = data.get("XSRF-TOKEN")
                        sid = data.get("SID")
                        self._cookies = requests.cookies.cookiejar_from_dict(data)
                else:
                    log.info("New SID is useable, store the cookies inside a json file for future use")
                    sid = login_cookie.get('SID', None)
                    self._cookies = login_cookie
                    with open("cookies.json", "w") as cookie_file:
                        json.dump(self._cookies.get_dict(), cookie_file)
            if not xsrf_token or not sid:
                retry -= 1
            else:
                log_in = True
        assert log_in, "Failed to log in"
        self._headers['SID'] = sid
        self._headers['X-Xsrf-Token'] = xsrf_token

    @retry_on_connection_error(retries=3)
    def get(self, url, params=None, allow_redirects=True, timeout=None, stream=False) -> requests.models.Response:
        """Send GET request in current session"""
        response = self._session.get(url, headers=self._headers, verify=True, params=params,
                                     allow_redirects=allow_redirects, cookies=self._cookies, stream=stream)
        if response.status_code == 401 or response.status_code == 403:
            self._session.close()
            self._create_new_session()
            response = self._session.get(url, headers=self._headers, verify=True, params=params,
                                         allow_redirects=allow_redirects, timeout=timeout)
        log.debug(f"GET API response: {response}")
        return response

    @retry_on_connection_error(retries=3)
    def post(self, url, payload=None, params=None) -> requests.models.Response:
        """Send POST request in current session"""
        response = self._session.post(url=url, data=json.dumps(payload), headers=self._headers,
                                      params=params,
                                      verify=True,
                                      cookies=self._cookies)
        if response.status_code == 401 or response.status_code == 403:
            self._session.close()
            self._create_new_session()
            response = self._session.post(url=url, data=json.dumps(payload),
                                          headers=self._headers,
                                          params=params,
                                          verify=True)
        log.debug(f"POST API response: {response}")
        return response

    @retry_on_connection_error(retries=3)
    def put(self, url, payload=None, params=None) -> requests.models.Response:
        """Send PUT request in current session"""
        response = self._session.put(url=url, data=json.dumps(payload),
                                     headers=self._headers,
                                     verify=True, params=params,
                                     cookies=self._cookies)
        if response.status_code == 401 or response.status_code == 403:
            self._session.close()
            self._create_new_session()
            response = self._session.put(url=url, data=json.dumps(payload),
                                         headers=self._headers,
                                         verify=True, params=params)
        log.debug(f"PUT API response status code: '{response.status_code}', text: '{response.text}'")
        return response

    @retry_on_connection_error(retries=3)
    def patch(self, url, payload=None, params=None) -> requests.models.Response:
        """Send PATCH request in current session"""
        response = self._session.patch(
            url=url,
            data=json.dumps(payload),
            headers=self._headers,
            verify=True,
            params=params,
            cookies=self._cookies,
        )
        if response.status_code == 401 or response.status_code == 403:
            self._session.close()
            self._create_new_session()
            response = self._session.patch(
                url=url,
                data=json.dumps(payload),
                headers=self._headers,
                verify=True,
                params=params,
            )
        log.debug(f"PATCH API response: {response}")
        return response

    @retry_on_connection_error(retries=3)
    def delete(self, url, payload=None) -> requests.models.Response:
        """Send DELETE request in current session"""
        response = self._session.delete(url=url, data=json.dumps(payload),
                                        headers=self._headers, verify=True,
                                        cookies=self._cookies)
        if response.status_code == 401 or response.status_code == 403:
            self._session.close()
            self._create_new_session()
            response = self._session.delete(url=url, data=json.dumps(payload),
                                            headers=self._headers, verify=True)
        log.debug(f"DELETE API response: {response}")
        return response
