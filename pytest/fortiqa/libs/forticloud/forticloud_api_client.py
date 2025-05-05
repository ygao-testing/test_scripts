import json
import logging
import requests
import imaplib
import email
import re
import os
import time
from functools import wraps
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError
from fortiqa.tests import settings
from email.header import decode_header
from urllib.parse import urlparse, parse_qs
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timezone, timedelta

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


def get_latest_email(test_start_datetime: datetime):
    """
    This function connects to Yahoo's IMAP server to fetch the latest email with
    "Token code: <security_code>" subject from "Fortinet Customer Service and Support(noreply@fortinet-notifications.com)",
    extracts <security_code>,and deletes the email afterward.

    Args:
        test_start_datetime: The datetime before calling this function.

    Returns:
        str: The FortiCloud security code value extracted from the email or an empty string if no email is found.
    """
    mail = imaplib.IMAP4_SSL("imap.mail.yahoo.com")
    mail.login(settings.app.customer['user_email'], settings.app.customer['user_email_password'])
    folders_to_check = ['Inbox', 'Archive']
    yesterday = (test_start_datetime - timedelta(days=1)).strftime("%d-%b-%Y")

    security_token = None
    for folder in folders_to_check:
        mail.select(folder)
        # Search for all emails within the past 24 hours from "Fortinet Customer Service and Support"
        _, messages_account = mail.search(None, f'(SINCE "{yesterday}" FROM "noreply@fortinet-notifications.com")')
        messages_account = messages_account[0].split()
        if not messages_account:
            log.info(f"Not receiving any FortiCloud security code email under {folder}")
        else:
            messages = messages_account
            log.info(f"Received FortiCloud security code code email under {folder}")
            latest_email_id = messages[-1]
            _, msg_data = mail.fetch(latest_email_id, "(RFC822)")

            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        # Need extra decode if subject is not a str
                        subject = subject.decode(encoding if encoding else "utf-8")
                    body = msg.get_payload(decode=True).decode()  # type: ignore
                    match = re.search(r'Your authentication token code is (\d{6})', body)
                    if match:
                        security_token = match.group(1)
                        date_header = msg["Date"]
                        email_date = email.utils.parsedate_to_datetime(date_header)
                        email_date_utc = email_date.astimezone(timezone.utc)
                        log.info(
                            f"Found FortiCloud security token: {security_token}, it was sent on {email_date_utc} UTC time")
                        if email_date_utc < test_start_datetime:
                            # Email was sent before the Test start time
                            log.debug(
                                f"Login process started on {test_start_datetime} UTC, but did not find login security token email after that")
                            security_token = None
            mail.store(latest_email_id, '+FLAGS', '\\Deleted')
            mail.expunge()
            mail.close()
            if security_token:
                mail.logout()
                return security_token
    mail.logout()
    if not security_token:
        log.debug("Not receiving any FortiCloud security code email under both Inbox and Archive folders")
    return ""


class FortiCloudApiClient(object):
    """
    Access Lacework portal as FortiCloud user.
    Since FortiCloud integration is only between:
        1. FortiCloud production (support-dev.corp.fortinet.com) and Lacework production (login.lacework.net)
        2. FortiCloud dev (support-dev.corp.fortinet.com) and Lacework QAN (login.qan.corp.lacework.net)
    FortiCloud login method cannot be used on other environment, e.g. spork
    """

    def __init__(self, account: str, fc_username: str, fc_password: str) -> None:
        self.account = account
        self.fc_username = fc_username
        self.fc_password = fc_password
        # qan.corp is integrated with support-dev env
        self.fc_env = "support-dev" if "qan" in self.account.split(".")[-1] else "production"
        self.base_url = f"https://{self.account}.lacework.net"
        self.login_url = f"{self.base_url}/fis/login"
        self.saml_url = f"https://login{'.qan.corp' if self.fc_env == 'support-dev' else ''}.lacework.net/saml/acs/"
        self.url = f"{self.base_url}/api/v1"
        self.user_profile_url = f"{self.url}/profile/info"
        self._create_new_session()

    def __enter__(self):
        return self

    def __exit__(self, exception_type,
                 exception_value, exception_traceback) -> None:
        self._session.close()

    def _create_new_session(self):
        self._session = requests.session()
        self._headers = {'Content-type': 'application/json',
                         'Accountname': self.account}
        self._cookies = None
        self._login()

    def _login(self):
        """
        Simulate Customer FortiCloud login process

        First tries to use existing cookies from cookies.json.
        If cookies are invalid or don't exist, falls back to FortiCloud login.
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
                self._headers['Accountname'] = self.account
                try:
                    # Make a test API call to verify cookie validity
                    test_response = self._session.get(f"{self.url}/profile/info", headers=self._headers)
                    if test_response.status_code == 200:
                        log.info("Successfully reused existing cookies from cookies.json")
                        self._cookies = requests.cookies.cookiejar_from_dict(data)
                        return
                    log.info("Existing cookies are invalid, proceeding with FortiCloud login")
                except Exception as e:
                    log.info(f"Failed to validate existing cookies: {str(e)}")

        # Get SAMLRequest and RelayState from FIS Login response url
        fis_url_response = self._session.get(url=f"{self.login_url}", allow_redirects=True, verify=True)
        parsed_url = urlparse(fis_url_response.url)
        query_params = parse_qs(parsed_url.query)
        saml_request = query_params.get('SAMLRequest', [None])[0]
        relay_state = query_params.get('RelayState', [None])[0]

        saml_login_url = fis_url_response.url
        auth_data = {
            "username": self.fc_username,
            "password": self.fc_password,
            "email-login-input": "on",
        }
        if saml_request and relay_state:
            # Get csrfmiddlewaretoken for authentication
            forticare_resp = self._session.get(
                saml_login_url,
                data={
                    'SAMLRequest': saml_request,
                    'RelayState': relay_state,
                },
                verify=True,
            )
            soup = BeautifulSoup(forticare_resp.text, "html.parser")
            csrfmiddlewaretoken = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            if csrfmiddlewaretoken:
                auth_data['csrfmiddlewaretoken'] = csrfmiddlewaretoken.get('value')
        else:
            log.warning('No SAMLRequest')

        log.info(f"saml_login_url::: {saml_login_url}")
        current_time_utc = datetime.now(timezone.utc)
        if self.fc_env == "production":
            # Wait 1 minute to make sure won't get the security token from the email before this test
            time.sleep(60)
        # Provide FortiCloud username and password
        saml_login_url_response = self._session.post(
            saml_login_url,
            data=auth_data,
            headers={"Referer": f"{saml_login_url}"},
            verify=True,
            allow_redirects=True,
        )
        soup = BeautifulSoup(saml_login_url_response.text, "html.parser")

        if self.fc_env == "production":
            # Need to provide Security Code from email when login to FortiCloud production
            time.sleep(15)  # Wait to receive new email
            security_token = get_latest_email(test_start_datetime=current_time_utc)
            assert security_token, "No security code email received. Unable to proceed with authentication."
            auth_data = {
                "username": self.fc_username,
                "token_code": security_token,
            }
            # Get new csrfmiddlewaretoken for Security Code authentication
            csrfmiddlewaretoken = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            if csrfmiddlewaretoken:
                auth_data['csrfmiddlewaretoken'] = csrfmiddlewaretoken.get('value')

            saml_login_url_response = self._session.post(
                saml_login_url,
                data=auth_data,
                headers={"Referer": f"{saml_login_url}"},
                verify=True,
                allow_redirects=True,
            )
            soup = BeautifulSoup(saml_login_url_response.text, "html.parser")

        saml_response_token = soup.find('input', {'name': 'SAMLResponse'}).get('value')
        log.info(f"{saml_response_token=}")
        saml_url_response = self._session.post(self.saml_url,
                                               data=dict(SAMLResponse=saml_response_token,
                                                         RelayState="/fis/select_role"),
                                               allow_redirects=True,
                                               headers={"Referer": "https://customersso1.fortinet.com/"},
                                               verify=True)

        assert saml_url_response.history, "SAML didn't redirect correctly, FortiCloud login failed."
        login_cookies = saml_url_response.cookies
        login_cookies_dict = login_cookies.get_dict()
        xsrf_token = login_cookies_dict.get('XSRF-TOKEN', None)
        SID = login_cookies_dict.get('SID', None)
        log.debug(f"CookieJar: {login_cookies}")
        log.debug(f"Xsrf-Token: {xsrf_token}")
        self._cookies = login_cookies
        self._xsrftoken = xsrf_token
        self._headers['X-Xsrf-Token'] = self._xsrftoken
        self._headers['SID'] = SID

        # Test if login successful
        assert self.is_logged_in(), "FortiCloud Login failed. Please verify that the provided credentials are correct."

        # Save cookies for future use
        if xsrf_token and SID:
            log.info("SID is useable, store the cookies inside a json file for future use")
            with open("cookies.json", "w") as cookie_file:
                json.dump(self._cookies.get_dict(), cookie_file)

    def is_logged_in(self) -> bool:
        """Return True is current session is authorized and False otherwise"""
        response = self._session.get(self.user_profile_url,
                                     cookies=self._cookies,
                                     headers={'X-Xsrf-Token': self._xsrftoken,
                                              'Content-type': 'application/json',
                                              'Referer': "https://customersso1.fortinet.com/"},
                                     verify=True)
        match response.status_code:
            case 200:
                log.info(f"Login attempt to FortiCloud successfully. account_profile={response.json()}")
                return True
            case 401:
                log.info("Login attempt to FortiCloud failed")
                return False
            case other:
                raise Exception(f"Unexpected status_code from {self.user_profile_url}: {other}")

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
