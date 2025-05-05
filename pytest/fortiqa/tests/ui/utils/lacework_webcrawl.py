from seleniumbase import BaseCase
import time
import logging

from fortiqa.tests.ui.data import base_xpaths
from fortiqa.libs.lw.apiv1.api_client.api_v1_client import get_latest_email
from fortiqa.tests import settings
from datetime import datetime, timezone

log = logging.getLogger(__name__)


class BasePage(BaseCase):
    def __init__(self, sb=None):
        self._sb = sb if sb else self
        super(BasePage, self).__init__()


class HomePage(BasePage):
    def open_page(self, user_email: str, url: str, first_login: bool = True) -> None:
        """
        Base method to login lacework instance
        :param user_email: User email account
        :param url: Lacework URL
        :param first_login: Login flag
        :return None
        """
        try:
            current_time_utc = datetime.now(timezone.utc)
            account = settings.app.customer['account_name']
            account_name = account.split(".")[0]
            subaccount = settings.app.customer['sub_account']
            self._sb.open(url)
            self._sb.click(base_xpaths.signin_link)
            self._sb.type(base_xpaths.email_input, user_email)
            self._sb.click(base_xpaths.get_signin_link)
            time.sleep(60)
            url += '/ui/otl?SID=' + get_latest_email(account_name, subaccount, current_time_utc)
            self._sb.open(url)
            if first_login:
                self._sb.click(base_xpaths.login_button)
                time.sleep(30)
            return None
        except Exception as e:
            log.info(f"Error in Lacework login: {e}")


class LaceworkPage(HomePage):
    def open_page(self, user_email: str, url: str, first_login: bool = True) -> None:
        """
        Method login lacework
        :param user_email: User email account
        :param url: Lacework URL
        :return None
        """
        try_counter = 0
        max_tries = 3
        lacework_ready = False
        while not lacework_ready and try_counter < max_tries:
            try:
                url = super(LaceworkPage, self).open_page(user_email, url, first_login)
                lacework_ready = True
            except Exception as e:
                if try_counter < max_tries:
                    log.warning(f"Failed to access Lacework page: {e}; Will retry after 30 seconds")
                    time.sleep(30)
            finally:
                try_counter += 1
                first_login = False
        return None

    def verify_documentation_links(self, url: str, visited_sites=None) -> tuple | None:
        """
        Method verify lacework documentation links
        :param url: Lacework URL
        :param visited_sites: List containing the visited links to prevent duplicates
        :return List of html links or None
        """
        if visited_sites is None:
            visited_sites = []
            self.fortinet_documentation_links: list[str] = []
            self.lacework_documentation_links: list[str] = []
        if url in visited_sites:
            return None
        visited_sites.append(url)

        try:
            self._sb.open(url)
            time.sleep(5)
            self._sb.maximize_window()
            time.sleep(5)
            soup = self._sb.get_beautiful_soup(self._sb.get_page_source())
            time.sleep(5)
            urls = soup.findAll("a")

            for a in urls:
                if a.get("href"):
                    if a.get("href").startswith("https://"):
                        html_link = a.get("href")
                        if html_link not in self.fortinet_documentation_links and html_link not in self.lacework_documentation_links:
                            if 'fortinet.com' in a.get("href"):
                                self.fortinet_documentation_links.append(html_link)
                            else:
                                self.lacework_documentation_links.append(html_link)
            else:
                return self.fortinet_documentation_links, self.lacework_documentation_links
        except Exception as e:
            log.info(f"Error in web crawling: {e}")
        return None
