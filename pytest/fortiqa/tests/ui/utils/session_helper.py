"""Session Helper"""
import logging
from time import sleep

from fortiqa.tests import settings
from fortiqa.tests.ui.utils.base_helper import BaseUiHelper

from fortiqa.tests.ui.utils.webelements_helper import close_menu_btn, left_menu_text, logout_button, open_menu_btn, \
    username_text, switch_account_btn, notification, notification_close

info = logging.getLogger(__name__).info
debug = logging.getLogger(__name__).debug

account_name = settings.app.customer['account_name']
sub_account = settings.app.customer['sub_account']


class SessionUiHelper(BaseUiHelper):
    """Session Helper"""

    def login_as_user(self, login_url: str):
        """
        Login as a particular user.
        :param login_url: Login URL from Email
        """
        info(f"login_as_user(), {login_url=}")
        self.driver.get(login_url)
        self.wait_until_loading_sign_disappears()
        if sub_account:
            if not self.is_logged_in_as():
                # Switch to sub_account
                self.click(username_text)
                self.click_by_text("All accounts")
                self.click(switch_account_btn.replace("account_name", sub_account.upper()))
                sleep(5)
                self.wait_until_loading_sign_disappears()
        self.close_notification()

    def close_notification(self):
        """Close notifications on the top right."""
        info("close_notification()")
        max_retries = 30
        attempts = 0
        while self.is_element_present(notification) and attempts < max_retries:
            self.click(notification_close)
            sleep(1)
            attempts += 1
        if attempts == max_retries and self.is_element_present(notification):
            debug(f"Unable to close notification after {max_retries} attempts.")

    def is_logged_in(self) -> bool:
        """Verify the page after login"""
        info("is_logged_in()")
        self.driver.implicitly_wait(2)
        # Check if the side menu is opened or closed. Open the menu if it is necessary.
        if self.is_element_present(close_menu_btn):
            self.driver.implicitly_wait(settings.ui.default_implicit_wait)
            return True
        elif self.is_element_present(open_menu_btn):
            self.click(open_menu_btn)
            self.driver.implicitly_wait(2)
            elements_present = len(self.get_elements(left_menu_text)) >= 10
            self.driver.implicitly_wait(settings.ui.default_implicit_wait)
            return elements_present
        return False

    def is_logged_in_as(self) -> bool:
        """
        Verify the Username
        :return: actual_username == expected_username
        """
        account = sub_account if sub_account else account_name.split('.')[0]
        visible_username = account.upper()
        info(f"is_logged_in_as(), {visible_username=}")
        sleep(2)
        return visible_username == self.get_text(username_text)

    def login(self, login_url: str):
        """
        Ensure login:
        1. If we already logged in, we verify username
        2. If username is correct - return, else - logout
        3. login one more time with correct credentials
        :param login_url: Login URL from Email
        """
        info("login()")
        if self.is_logged_in():
            if self.is_logged_in_as():
                self.close_notification()
                return
            # self.logout()
        self.login_as_user(login_url)
        assert self.is_logged_in_as(), f"Failed to login as {account_name=}, {sub_account=}"

    def logout(self):
        """
        Logout:
        1. Log out through GUI
        2. Verify logout page
        """
        info('logout()')
        info('1. Log out through GUI')
        info('Open sub menu')
        self.click(username_text)
        self.click(logout_button)

        info('2. Verify logout page')
