"""Elements Helper class"""
import logging
import re

from selenium.common import WebDriverException
from selenium.common.exceptions import TimeoutException
from selenium.webdriver import ActionChains, Keys
from selenium.webdriver.common.by import By
from time import sleep

from fortiqa.tests.ui.data.pages import pages, tabs
from fortiqa.tests import settings
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

info = logging.getLogger(__name__).info
debug = logging.getLogger(__name__).debug

# Buttons #
button = '//button/span[text()="visible_text"]'
download_btn = '//button[contains(@data-testid,"download")]'

# Main Left Menu
left_menu_item = '(//div[@class="side-nav-link-text"]/div[text()="visible_text"])[last()]'
left_menu_text = '//div[@class="side-nav-link-text"]/div'
settings_menu_item = '//li[text()="visible_text" and @role="menuitem"]'
button_with_submenu = '//button[contains(@class,"side-nav-trigger")]'
open_menu_btn = '//button[@title="Pin the side nav"]'
close_menu_btn = '//button[@title="Unpin the side nav"]'
selected_item_with_submenu = '//button[@class="side-nav-trigger side-nav-trigger--has-active-children"]//div[@class="side-nav-link-text"]/div'
selected_item_without_submenu = '//a[@class="side-nav-link side-nav-leaf-link is-active"]//div[@class="side-nav-link-text"]/div'
selected_item_in_submenu = '//li[contains(@class,"ant-menu-item-selected")]'

# Login
# dashboard_button = '//button[@class="LaceworkLogo_laceworkLogoButton__faSEo"]'
username_text = '//button[@class="side-nav-trigger side-nav-trigger-select-text"]'
logout_button = '//button//div[text()="Log out"]'
google_username_input = '//input[@id="identifierId"]'
fortinet_username_input = '//input[@id="id_username"]'
fortinet_password_input = '//input[@id="id_password"]'
submit_btn = '//input[@type="submit"]'
switch_account_btn = '//div[contains(@class,"ChangeAccountsPage_accounts")]/button//div[text()="account_name"]'
notification = '//div[contains(@class, "ant-notification-topRight")]//div[contains(@class,"closable")]'
notification_close = notification + '//span[@class="ant-notification-close-x"]'

# Data from the sections
section_title = '//div[text()="section_name"]'
section_data_text = section_title + '/../following-sibling::div//span[text()="title_name"]/preceding-sibling::span[@class="trellis-legend-value"]'
section_data_link = section_title + '/../following-sibling::div//span[text()="title_name"]/../../following-sibling::button'
# these sections are located in "Vulnerabilities/Host" Dashboard area
vuln_host_section_text = section_title + '/ancestor::div[@data-track="vulnerability-host.dashboard.dashboard-collapse"]//div[text()="element_name"]/ancestor::div[contains(@data-testid,"vulnerability-summary-kpi")]/div[2]'
empty_section = section_title + '/ancestor::div[contains(@class,"trellis-collapse-skeleton-expanded")]//p'

# Data from the sections with graph
text_from_section_with_graph = section_title + '/ancestor::div[@role="button"]//div[contains(@class,"trellis-legend-entry")]/span[text()="title_name"]/preceding-sibling::span[@class="trellis-legend-value"]'
no_data_text_from_section_with_graph = section_title + '/ancestor::div[@role="button"]//div[@data-testid]'

# Tabs
tab_title_button = '//span[@class="trellis-nav-tabs-trigger-focus-area" and text()="tab_title"]/ancestor::button'
tab_title_button_with_sub_tab = '//span[@class="trellis-nav-tab-select-value" and contains(text(),"tab_title")]'
sub_title_button = '//div[@class="trellis-nav-tab-select-item-text"]/span[text()="sub_tab_title"]'

# Tooltip
tooltip_btn = '//div[@role="heading" and text()="title_name"]/following-sibling::span[@class="trellis-infotip"]/button'
tooltip_text = '//div[@class="ant-popover-inner" and @role="tooltip"]/../parent::div[not(contains(@class, "hidden"))]'

# Search
search_field = '//input[@placeholder="visible_text" and @type="search"]'
search_result = '//button//div[text()="visible_text"]'

# Dropdown list
dropdown_list = '(//div[contains(text(),"visible_text")]/following-sibling::div//div[contains(@class,"selector")])[position]'
dropdown_right_text_area = '//div[contains(@class,"SavedQueryDetails_infoContentContainer__XxiHB")]'

# Table
pagination_xpath = '//span[@class="trellis-pagination-label"]'  # e.g. "1 - 10 of 15"

# Other
loading_indicator = '//div[contains(@class, "ant-spin-spinning")]'
text_element = '(//*[text()="visible_text"])[position]'
contains_text_element = '(//*[contains(text(),"visible_text")])[position]'

# checkbox
checkbox = '//span[contains(text(), "visible_text")]/preceding-sibling::span[contains(@class, "checkbox")]'

# Input
text_input = '(//div[contains(text(),"visible_text")]/following-sibling::span//input)[position]'
text_filed_error = '//div[contains(text(),"visible_text")]/following-sibling::*[contains(@class, "error")]'


class WebElementsHelper:
    """Web Elements helper. An ancestor of all classes. It doesn't have a parent class."""

    def __init__(self, app):
        self.driver = app.driver

    # CLICK #
    def click(self, xpath: str):
        """
        Click a Web Element
        :param xpath: xpath
        """
        self.driver.find_element(By.XPATH, xpath).click()

    def click_btn(self, text: str, base_xpath=""):
        """
        Click a button
        :param text: text on the button
        :param base_xpath: base xpath
        """
        xpath = base_xpath + button.replace("visible_text", text)
        self.click(xpath)

    def click_download_btn(self, base_xpath=''):
        """
        Click a download button
        :param base_xpath: base xpath
        """
        self.click(base_xpath + download_btn)

    def click_by_text(self, text: str, base_xpath="", position="1", partial: bool = False):
        """
        Click by element with a particular text.
        :param text: text
        :param base_xpath: base xpath
        :param position: specify the location of text
        :param partial: True for specified text is only part of the whole string on the page
        """
        xpath = contains_text_element if partial else text_element
        if base_xpath:
            xpath = xpath[:1] + base_xpath + xpath[1:]
        self.click(xpath.replace("visible_text", text).replace("position", position))

    # PAGE #
    def open_page(self, name: str):
        """
        Click left menu item
        1. Open left menu
        2. Click menu item
        3. Verify page
        :param name: page name
        """
        info(f"open_page(), {name=}")
        self.driver.implicitly_wait(10)
        expected_url = "https://" + settings.app.customer["account_name"] + ".lacework.net/ui/investigation" + \
                       pages[name]["url"]
        actual_url = self.driver.current_url.split("?")[0]
        if actual_url == expected_url:
            self.driver.refresh()
            self.wait_until_loading_sign_disappears()
        else:
            info(f"Open '{name}' page")
            xpath_1 = ""
            xpath_2 = ""
            xpath_3 = ""
            visible_username = settings.app.customer['account_name'].split('.')[0].upper()
            if name in ["AWS Cloudtrail", "Azure Activity Log", "GCP Audit Log"]:
                xpath_1 = left_menu_item.replace("visible_text", "Cloud logs")
            elif name in ["Workloads Hosts", "Workloads Containers", "Workloads Kubernetes"]:
                xpath_1 = left_menu_item.replace("visible_text", "Workloads")
                xpath_2 = left_menu_item.replace("visible_text", name.split(" ")[1])
            elif name in ["Top work items", "Path investigation"]:
                xpath_1 = left_menu_item.replace("visible_text", "Attack path")
            elif name in ["Compliance Cloud", "Compliance Kubernetes"]:
                xpath_1 = left_menu_item.replace("visible_text", "Compliance")
                xpath_2 = left_menu_item.replace("visible_text", name.split(" ")[1])
            elif name in ["Vulnerabilities Host", "Vulnerabilities Vulnerabilities", "Vulnerabilities Containers",
                          "Exceptions"]:
                xpath_1 = left_menu_item.replace("visible_text", "Vulnerabilities")
                xpath_2 = left_menu_item.replace("visible_text", name.split(" ")[1])
            elif name in [visible_username, "All accounts", "Log outs"]:
                xpath_1 = left_menu_item.replace("visible_text", visible_username)
            elif name in ["Infrastructure (IaC)", "Applications"]:
                xpath_1 = left_menu_item.replace("visible_text", "Code security")
                xpath_2 = left_menu_item.replace("visible_text", name.split(" ")[1])
            elif name in ["Channels", "Cloud accounts", "Container registries", "Security in Jira", "Resource groups",
                          "API keys", "Agent Tokens", "Risk score", "General", "License", "Subscription",
                          "Subscription Usage", "Audit logs", "Roles", "User groups", "Users", "My profile",
                          "Onboarding"]:
                xpath_2 = left_menu_item.replace("visible_text", "Settings")
                xpath_3 = settings_menu_item.replace("visible_text", name)
            if xpath_1:
                self.move_to_element(xpath_1)
                sleep(1)
            if xpath_2:
                self.click(xpath_2)
            else:
                self.click(left_menu_item.replace("visible_text", name))
            if xpath_3:
                self.click(xpath_3)
            sleep(1)
        self.wait_until_loading_sign_disappears()
        self.verify_current_page(name)

        self.driver.implicitly_wait(settings.ui.default_implicit_wait)

    def verify_current_page(self, name: str):
        """
        Verify current page:
        1. Verify active item in the left menu
        2. Verify URL
        # TODO: Implement this part
        3. Header text (name of the page)
        :param name: page name
        """
        info(f"verify_current_page(), {name=}")
        error = ""
        info("1. Verify active item in the left menu")
        # Get title of the Selected element in the left menu
        xpath_submenu = ""
        if name in ["Dashboard", "Explorer", "Resource Explorer", "Resource Inventory", "Alerts", "Identities",
                    "Policies", "Frameworks", "Reports", "Agents", "Agentless", "Settings"]:
            xpath = selected_item_without_submenu
        # For "Settings"
        elif name in ["Channels", "Cloud accounts", "Container registries", "Security in Jira", "Resource groups",
                      "API keys", "Agent Tokens", "Risk score", "General", "License", "Subscription",
                      "Subscription Usage", "Audit logs", "Roles", "User groups", "Users", "My profile",
                      "Onboarding"]:
            xpath = selected_item_without_submenu
            xpath_submenu = selected_item_in_submenu
        elif name in ["AWS Cloudtrail", "Azure Activity Log", "GCP Audit Log",  # Cloud logs
                      "Workloads Hosts", "Workloads Containers", "Workloads Kubernetes",  # Workloads
                      "Top work items", "Path investigation",  # Attack path
                      "Compliance Cloud", "Compliance Kubernetes",  # Compliance
                      "Vulnerabilities Host", "Vulnerabilities Vulnerabilities", "Vulnerabilities Containers",
                      "Exceptions",
                      # Vulnerabilities
                      "Infrastructure (IaC)", "Applications",  # Code security
                      ]:
            xpath = selected_item_with_submenu
        elif name in ["Help", "All accounts"]:
            # TODO: Probably there is a GUI Bug: for "All accounts" the menu item should be selected
            xpath = ""
        else:
            xpath = ""
            error += f"\nName '{name}' is not identified"

        if xpath:
            selected_title = self.get_text(xpath)
            expected_title = pages[name]["left_menu"]
            if selected_title != expected_title:
                error += f"\nSelected item is '{selected_title},\n but expected is '{expected_title}'"
        if xpath_submenu:
            selected_submenu_title = self.get_text(xpath_submenu)
            if selected_submenu_title != name:
                error += (f"\nSelected item in submenu is '{selected_submenu_title},"
                          f"\n but expected item in submenu is '{name}'")

        info("2. Verify URL")
        expected_url = "https://" + settings.app.customer["account_name"] + ".lacework.net/ui/investigation" + \
                       pages[name]["url"]
        if name in ["Vulnerabilities Vulnerabilities"]:
            expected_url = expected_url.replace("/investigation", "")
        self.verify_url(expected_url)

        info("3. Header text (name of the page)")
        # TODO: Implement this part

        assert not error, error

    def click_tab(self, tab_title: str, sub_tab: str = "", timeout=20, verify_only: bool = False):
        """
        Click on the tab on the top of the table.
        :param tab_title: title of the tab
        :param sub_tab: Sub Tab name
        :param timeout: max waiting timeout
        :param verify_only: True for verify the tab details only without clicking the tab
        """
        info(f"click_tab(), {tab_title=}")
        xpath = tab_title_button_with_sub_tab.replace("tab_title", tab_title) if sub_tab else tab_title_button.replace(
            "tab_title", tab_title)
        if not verify_only:
            info("1. Click on the tab")
            if sub_tab:
                self.click(xpath)
                sleep(1)
                self.click(sub_title_button.replace("sub_tab_title", sub_tab))
            else:
                self.click(xpath)
            self.wait_until_loading_sign_disappears(timeout=timeout)

        info("2. Verify tab")
        error = ""
        if sub_tab:
            error += self.verify_text(xpath, expected_text=sub_tab, partial=True)
        else:
            tab_selected = self.get_element(xpath).get_attribute("aria-selected")
            if tab_selected != "true":
                error += f"\nTab '{tab_title}' is not selected"
        assert not error, error

        info("3. Verify URL")
        expected_url = "https://" + settings.app.customer["account_name"] + ".lacework.net/ui/investigation" + tabs[
            tab_title]
        if tab_title in ["Overview", "Top items", "Explore"]:
            expected_url = expected_url.replace("/investigation", "")
        self.verify_url(expected_url)

    # URL #
    def wait_for_url(self, expected_url: str, waiting_time: int = 5) -> str:
        """
        Wait for URL for "waiting_time" sec.
        :param expected_url: expected URL
        :param waiting_time: max waiting time
        :return: an error message or an empty sting
        """
        info(f"wait_for_url(), {expected_url=}, {waiting_time=}")
        actual_url = ''
        for _ in range(waiting_time):
            sleep(1)
            actual_url = self.driver.current_url
            # actual_url could have query or time range at the end of URL by default
            if expected_url in actual_url:
                return ''
        return f"\n  {actual_url=}, but\n{expected_url=}"

    def verify_url(self, expected_url: str, waiting_time: int = 5, return_error_text: bool = False) -> None | str:
        """
        Verify URL
        :param expected_url: expected URL
        :param waiting_time: max waiting time
        :param return_error_text: return an Error Text if we verify it outside the method
        :return: Error Text
        """
        info(f"verify_url(), {expected_url=}, {waiting_time=}")
        error = self.wait_for_url(expected_url, waiting_time)
        if return_error_text:
            return error
        assert not error, error
        return None

    # ELEMENT #

    def get_element(self, xpath: str):
        """
        Get element
        :param xpath: xpath
        :return: Web element (type: selenium.webdriver.remote.webelement.WebElement)
        """
        return self.driver.find_element(By.XPATH, xpath)

    # ELEMENTS #

    def get_elements(self, xpath: str) -> list:
        """
        Get elements
        :param xpath: xpath
        :return: list of elements
        """
        return self.driver.find_elements(By.XPATH, xpath)

    # NAVIGATION TO ELEMENT #

    def move_to_element(self, xpath: str):
        """
        Move mouse to an element
        :param xpath: xpath
        """
        ActionChains(self.driver).move_to_element(self.get_element(xpath)).perform()

    def move_viewport_to_element(self, xpath: str):
        """
        Move viewport to make sure the element is included
        :param xpath: xpath
        """
        self.driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", self.get_element(xpath))

    def move_to_element_and_scroll_down(self, xpath: str, move_down=False):
        """
        Move mouse to an element, click and scroll down (using the "PAGE_DOWN" button)
        :param xpath: xpath
        :param move_down: move down a little bit for table titles with tag "a" (an anchor with a hyperlink)
        """
        action = ActionChains(self.driver)
        # move_to_element() doesn't work for Firefox if element is out of viewport dimensions
        self.move_viewport_to_element(xpath)
        sleep(1)
        if move_down:
            action.move_to_element(self.get_element(xpath)).move_by_offset(0, 20).click().perform()
            action.send_keys(Keys.PAGE_DOWN).perform()
        else:
            action.move_to_element(self.get_element(xpath)).click().send_keys(Keys.PAGE_DOWN).perform()

    # GET PARAMETERS OF ELEMENT #

    def get_text(self, xpath: str) -> str:
        """
        Get Text of an element
        :param xpath: xpath
        :return: Text of an element
        """
        return self.driver.find_element(By.XPATH, xpath).text

    def get_text_from_several_elements(self, xpath: str) -> str:
        r"""
        Get Text from several elements
        :param xpath: xpath
        :return:  Text of several elements. Each new line separated by "\n"
        """
        result = []
        for element in self.get_elements(xpath):
            result.append(element.text)
        return "\n".join(result)

    # GET DATA FROM THE SCREEN #
    def get_tooltip_by_title(self, title: str) -> str:
        """
        Return tooltip text by the title name
        :param title: Title for the tooltip text.
        :return: tooltip text
        """
        self.move_to_element(tooltip_btn.replace("title_name", title))
        sleep(1)
        return self.get_text(tooltip_text).split("\n")[0]

    def get_text_from_section(self, section_name: str, title_name: str, sub_section=False) -> str:
        """
        # TODO: Also we can create a method what go throw all elements and save the data in the dict: {"Critical":"6", "High":"22"}
        Get text from Sections
        :param section_name: section name
        :param title_name: title name
        :param sub_section: True for section_name is for the sub section, which is one level different
        :return: text
        """
        xpath = section_data_text.replace("section_name", section_name).replace("title_name", title_name)
        if sub_section:
            xpath = xpath.replace("/../", "/../../")
        return self.get_text(xpath)

    def get_text_from_section_with_graph(self, section_name: str, title_name: str = "") -> str:
        """
        Get text from a section with a graph
        :param section_name: section name
        :param title_name: title name
        """
        if title_name:
            xpath = text_from_section_with_graph.replace("section_name", section_name).replace("title_name", title_name)
        else:
            xpath = no_data_text_from_section_with_graph.replace("section_name", section_name)
        return self.get_text(xpath)

    # ELEMENT #

    def wait_until_loading_sign_disappears(self, timeout=20):
        """
        Wait until the loading sign disappears if it initially presents on the screen.
        :param timeout: max waiting timeout
        """
        self.wait_until_element_disappears(loading_indicator, timeout)
        sleep(1)

    def wait_until_element_disappears(self, xpath: str, timeout=20):
        """
        Wait until a web element disappears if the element initially presents on the screen.
        :param xpath: xpath of the web element
        :param timeout: max waiting timeout
        """
        # We need "is_element_present()" because without it "invisibility_of_element_located()" waits for
        # implicitly_wait (10) sec if the loading sign is not present on the screen
        try:
            if self.is_element_present(xpath):
                WebDriverWait(self.driver, timeout).until(EC.invisibility_of_element_located((By.XPATH, xpath)))
        except TimeoutException:
            debug(f"Timeout: Element with XPath '{xpath}' did not disappear within {timeout} seconds.")

    def wait_until_element_appears(self, xpath: str, timeout=20):
        """
        Wait until a web element appears on the screen.
        :param xpath: xpath of the web element.
        :param timeout: Max waiting timeout
        """
        try:
            if not self.is_element_present(xpath):
                WebDriverWait(self.driver, timeout).until(EC.presence_of_element_located((By.XPATH, xpath)))
        except TimeoutException:
            debug(f"Timeout: Element with XPath '{xpath}' did not appear within {timeout} seconds.")

    def is_element_present(self, xpath):
        """
        Check if the element is present on the screen.
        :param xpath: xpath
        :return: If the element present on the screen the method returns True, otherwise False
        """
        self.driver.implicitly_wait(2)
        elements = self.driver.find_elements(By.XPATH, xpath)
        self.driver.implicitly_wait(settings.ui.default_implicit_wait)
        return bool(elements)

    def is_text_present(self, text: str):
        """
        Check if the text is present on the screen.
        :param text: expect text
        :return: If the text present on the screen the method returns True, otherwise False
        """
        return self.is_element_present(contains_text_element.replace("visible_text", text))

    # TYPE #

    def type_text(self, xpath: str, text: str):
        """
        Clear an input and type a text
        :param xpath: xpath
        :param text: text
        """
        element = self.driver.find_element(By.XPATH, xpath)
        if not text:
            element.send_keys('x')
            self.clear_text_input_manually(xpath)
        elif element.text != text:
            element.clear()
            element.send_keys(text)

    def clear_text_input_manually(self, xpath):
        """
        Clear text input manually by pressing "Control" + "A" and "Delete" button on the keyboard
        :param xpath: xpath
        """
        element = self.driver.find_element(By.XPATH, xpath)
        element.send_keys(Keys.CONTROL, 'a')
        element.send_keys(Keys.DELETE)

    # VERIFICATIONS #
    def verify_text(self, xpath: str = "", expected_text: str = "", actual_text: str = "",
                    re_pattern: bool = False, partial: bool = False) -> str:
        """
        Verify text on the page with expected value
        :param xpath: xpath of the actual text element
        :param expected_text: expected text value
        :param actual_text: if not empty, directly verify the actual_text with expected_text
        :param re_pattern: Using regular expression as a pattern to verify the format only
        :param partial: True for actual_text contains expected_text
        :return: an error message or an empty string if verification passes
        """
        info(f"verify_text(), {xpath=}, {expected_text=}, {actual_text=}")
        try:
            if xpath and actual_text:
                raise ValueError(f"Couldn't provide both {xpath=} and {actual_text=}")
            elif not xpath and not actual_text:
                raise ValueError("Please provide either 'xpath' or 'actual_text'")
            elif xpath:
                actual_text = self.get_text(xpath)
            if re_pattern:
                pattern = re.compile(expected_text)
                if not pattern.match(actual_text):
                    return f"\n  {actual_text=}, but\n{expected_text=}\n"
                return ""
            elif partial:
                if expected_text not in actual_text:
                    return f"\n  {actual_text=}, but\n{expected_text=}\n"
                return ""
            else:
                if actual_text != expected_text:
                    return f"\n  {actual_text=}, but\n{expected_text=}\n"
                return ""
        except WebDriverException:
            return f"\nText with {xpath=} not found"

    def verify_text_field_error_message(self, title: str = "", expected_text: str = "") -> str:
        """
        Verify text field error message on the page with expected value
        :param title: title of the text field
        :param expected_text: expected text value
        :return: an error message or an empty string if verification passes
        """
        info(f"verify_text(), {title=}, {expected_text=}")
        try:
            actual_text = self.get_text(text_filed_error.replace("visible_text", title))
            if actual_text != expected_text:
                return f"\n  {actual_text=}, but\n{expected_text=}\n"
            return ""
        except WebDriverException:
            return f"\nError message under {title=} not found."

    # MULTI WINDOWS
    def switch_to_new_window(self) -> str:
        """
        Switch the window handle to the new window, allowing actions on the other window.
        Store the current window handle to switch back later.
        We restrict the page numbers since we only need to switch between 2 pages.
        :return: Main window handle
        """
        main_window_handle = self.driver.current_window_handle
        new_window_handle = None
        page_num = len(self.driver.window_handles)
        assert page_num == 2, f"Unable to switch between pages, currently {page_num} pages are opened."

        for handle in self.driver.window_handles:
            if handle != main_window_handle:
                new_window_handle = handle
                break
        self.driver.switch_to.window(new_window_handle)
        return main_window_handle

    def close_page(self):
        """Close the current page."""
        self.driver.close()

    def switch_to_main_window(self, main_window_handle: str):
        """
        Switch a window handle to the Main window.
        :param main_window_handle: Main window handle for Selenium
        """
        self.driver.switch_to.window(main_window_handle)

    # SEARCH #

    def search_by_text(self, placeholder: str, value: str):
        """
        Search the element in the dropdown list through search field
        :param placeholder: the placeholder of the search field
        :param value: name of the target element
        """
        info(f"search_by_text(), {placeholder=}, {value=}")
        search_xpath = search_field.replace("visible_text", placeholder)
        sleep(0.2)
        self.type_text(search_xpath, value)
        sleep(1.5)
        info("Click on the search result")
        search_result_xpath = search_result.replace("visible_text", value)
        self.click(search_result_xpath)
        sleep(1)
        info("Verify the search result is selected")
        selected_dropdown_item = '//input[@placeholder="visible_text"]/ancestor::div//button[contains(@class,"viewed")]'
        selected_dropdown_item_xpath = selected_dropdown_item.replace("visible_text", placeholder)
        error = self.verify_text(xpath=selected_dropdown_item_xpath, expected_text=value)
        assert not error, error

    # TODO: Delete all commented out lines when we done with basic methods
    # def right_click_by_text(self, text, base_xpath='', position="1"):
    #     """
    #     Right click by element with particular text.
    #     :param text: text
    #     :param base_xpath: base xpath
    #     :param position: specify the location of text
    #     """
    #     act = ActionChains(self.driver)
    #     info(f'Right click by text "{text}".')
    #     xpath = text_element.replace("visible_text", text).replace("position", position)
    #     source = self.driver.find_element(By.XPATH, base_xpath + xpath)
    #     act.context_click(source).perform()
    #
    # def open_right_button_menu_and_click(self, text: str, action: str, position="1"):
    #     """
    #     Right-Click by element with particular text to open menu and click by particular text.
    #     :param text: text for right-click
    #     :param action: right menu element , e.g. Clone/Edit/Delete
    #     :param position: specify the location of text if we expect the same text several time on the screen
    #     """
    #     info("open_right_button_menu_and_click()")
    #     self.right_click_by_text(text=text, position=position)
    #     info("Click right menu element.")
    #     self.click_right_menu_element(action)
    #
    # def click_right_menu_element(self, action: str):
    #     """
    #     Click on a particular element in the right button menu
    #     :param action: name of an element in the right button menu
    #     """
    #     info(f"click_right_menu_element(), {action=}")
    #     xpath = right_menu_btn.replace("visible_text", action)
    #     self.click(xpath)
    #
    #
    # def click_btn_by_title(self, title, btn):
    #     """
    #     Some pages have buttons with the same name under different titles. This method is for clicking a button by its title:
    #     For example, in "Policy Set revision" in Edit AWS CNF, there are two "Diff" buttons under different titles.
    #     :param title: title name
    #     :param btn: button name
    #     """
    #     xpath = btn_by_title.replace("title_text", title).replace("btn_text", btn)
    #     self.click(xpath)
    #
    # def click_stage_label(self, text):
    #     """
    #     Click a stage label
    #     :param text: text on the stage label, e.g. label in "Edit AWS CNF", "New Policy Set Wizard"
    #     """
    #     xpath = stage_label.replace("visible_text", text)
    #     self.click(xpath)
    #
    # def double_click_by_text(self, text, partial=False, position="1"):
    #     """
    #     Doubleclick by element with particular text.
    #     :param text: text
    #     :param partial: True for double-click by partial text
    #     :param position: specify the location of text
    #     """
    #     action = ActionChains(self.driver)
    #     xpath = contains_text_element.replace("visible_text", text) if partial else text_element.replace("visible_text",
    #                                                                                                      text)
    #     xpath = xpath.replace("position", position)
    #     element = self.driver.find_element(By.XPATH, xpath)
    #     action.double_click(element).perform()
    #
    # def hold_ctrl_and_click_by_text(self, text_1: str, text_2: str):
    #     """
    #     Hold "ctrl" key and click 2 text elements:
    #     :param text_1: text of the 1st element
    #     :param text_2: text of the 2nd element
    #     Unfortunately the loop "for" with clicks doesn't work
    #     """
    #     xpath_1 = text_element.replace("visible_text", text_1).replace("position", "1")
    #     el_1 = self.get_element(xpath_1)
    #     xpath_2 = text_element.replace("visible_text", text_2).replace("position", "1")
    #     el_2 = self.get_element(xpath_2)
    #     ActionChains(self.driver).key_down(Keys.CONTROL).click(el_1).click(el_2).key_up(Keys.CONTROL).perform()
    #
    # def click_plus_btn_by_text(self, text: str, last: bool = False):
    #     """
    #     Click plus button with particular text.
    #     :param text: text
    #     :param last: True for clicking the last plus button on the page
    #     """
    #     xpath = dropdown_plus_btn.replace("visible_text", text)
    #     if last:
    #         xpath = "(" + xpath + ")[last()]"
    #     self.click(xpath)
    #
    # def click_cross_cancel_btn_by_text(self, text: str, sec_profile=False, last: bool = False):
    #     """
    #     Click "cross cancel" button with particular text.
    #     :param text: text
    #     :param sec_profile: True for "cross cancel" btn in Security Profile page
    #     :param last: True for clicking the last plus button on the page
    #     """
    #     xpath = cross_cancel_btn.replace("visible_text", text)
    #     if sec_profile:
    #         xpath = xpath.replace("nu-field[1]//", "")
    #     if last:
    #         xpath = "(" + xpath + ")[last()]"
    #     self.click(xpath)
    #
    # def click_refresh_btn_by_title(self, title: str):
    #     """
    #     Click the "Refresh" button (with a circle sign)
    #     :param title: title
    #     """
    #     xpath = refresh_btn.replace("visible_text", title)
    #     self.click(xpath)
    #     # wait for the "Loading" sign disappears
    #     self.wait_until_element_disappears(xpath + '/nu-icon[@class="loading"]')
    #
    # def click_new_menu_item(self, text: str):
    #     """
    #     Click the "New" menu item
    #     1. Open menu (click the "New" button)
    #     2. Click menu item
    #     :param text: text
    #     """
    #     self.click_btn("New")
    #     xpath = menu_item_btn.replace("visible_text", text)
    #     self.click(xpath)
    #
    # def close_popup_message(self):
    #     """Close the latest popup notification text by click on it"""
    #     if self.is_element_present(popup_notification_text):
    #         self.click(popup_notification_text)
    #         sleep(0.5)
    #
    # def click_popup_central_message(self, button_name: str):
    #     """
    #     Click on the buttons ("OK", "Cancel", etc.) that located in the central popup message
    #     :param button_name: button name
    #     """
    #     popup_central_message_btn_xpath = popup_central_message_btn.replace("visible_text", button_name)
    #     self.click(popup_central_message_btn_xpath)
    #

    #
    # def verify_current_page(self, name: str):
    #     """
    #     Verify current page:
    #     1. active item in the left menu
    #     2. URL
    #     :param name: page name
    #     """
    #     info(f"verify_current_page(), {name=}")
    #     if name in ["Policy Sets", "Addresses", "Services", "Security Profiles", "CNF Templates", "Audit Log",
    #                 "Tenant Info", "API keys"]:
    #         active_item_xpath = active_left_menu_item_lev_2
    #     else:
    #         active_item_xpath = active_left_menu_item
    #     error = ''
    #     actual_active_item = self.driver.find_element(By.XPATH, active_item_xpath).get_attribute("ariaLabel")
    #     if actual_active_item != name:
    #         error += f"\n actual active menu item == '{actual_active_item}',\nbut expected active item == '{name}'\n"
    #     actual_url = self.driver.current_url
    #     expected_url = settings.app.admin_portal_url + urls[name]
    #     if actual_url != expected_url:
    #         error += f"\n  {actual_url=}, but\n{expected_url=}"
    #     assert not error, error
    #
    # def open_page_with_hard_refresh(self, name):
    #     """
    #     1. Open the page.
    #     2. If the "spinning download" sign is present on the screen than open the 'Dashboard' page (because on this
    #     page we don't have a problem with the "spinning download") and open the target page again.
    #     NOTE: Sometimes a table on the "Cloud Accounts" page is empty (cannot download data, and we see only the
    #     "spinning download" sign). This bug is hard to reproduce and report. We must move to another page and return
    #     to see an actual table.
    #     """
    #     self.open_page(name)
    #     if self.is_element_present(loading_table_sign):
    #         self.open_page('Dashboard')
    #         self.open_page(name)
    #

    #
    # # TYPE #

    #
    # def paste_text(self, xpath: str):
    #     """
    #     Simulate Ctrl+V to paste text from the clipboard to the element at the xpath.
    #     :param xpath: xpath
    #     """
    #     element = self.get_element(xpath)
    #     element.send_keys(Keys.CONTROL, 'v')

    # CHECKBOX #

    def is_checkbox_checked(self, title: str = "") -> bool:
        """
        Get current value of the checkbox. If value == "True" the checkbox should be checked
        :param title: title text
        :return: "True" in the checkbox checked, otherwise "False"
        """
        checkbox_element = self.driver.find_element(By.XPATH, checkbox.replace("visible_text", title))
        actual_value = checkbox_element.get_attribute('className')
        if "checked" in actual_value:
            debug(f"Actual value of '{title}' checkbox is 'True'")
            return True
        debug(f"Actual value of '{title}' checkbox is 'False'")
        return False

    def set_checkbox(self, title: str, value: bool):
        """
        Set Checkbox value. If value == "True" the checkbox should be checked,
        if value == "False" the checkbox should be unchecked
        :param title: title
        :param value: "True" or "False"
        """
        # Get current value of the checkbox
        checkbox_element = self.driver.find_element(By.XPATH, checkbox.replace("visible_text", title))
        actual_value = self.is_checkbox_checked(title)
        if actual_value != value:
            checkbox_element.click()

    # def verify_popup_notification(self, expected_text, error=False, prefix=""):
    #     """
    #     Verify the Pop-up status notification in the bottom right corner
    #     :param expected_text: expected text
    #     :param error: True for error message, otherwise False
    #     :param prefix: Prefix of the popup text, usually is the obj name. e.g."API-KEY has been deleted successfully."
    #     """
    #     info(f"verify_popup_notification(), {expected_text=}")
    #     # TODO: Add more verifications: color, elements, etc.
    #     sleep(1)
    #     actual_text = self.driver.find_element(By.XPATH, popup_notification_text).text
    #     expected_text = expected_text if error else popup_message_text[expected_text]
    #     if prefix:
    #         expected_text = prefix + expected_text
    #     assert actual_text == expected_text, f"\n  {actual_text=}, but\n{expected_text=}"
    #     self.close_popup_message()

    # TEXT FIELDS #

    def set_text_field(self, title: str, value: str, position="1"):
        """
        Set input (field) by text (name of the input). Usually text located on the left side of the input
        :param title: title of the text field
        :param value: text
        :param position: specify the location of input, when it has several input
        """
        xpath = text_input.replace("visible_text", title).replace("position", position)
        # For text field
        self.type_text(xpath, value)

    # def get_text_field_numbers(self, title: str) -> int:
    #     """
    #     Get total number of text fields with given names
    #     :param title: title
    #     :return: numbers of input boxes
    #     """
    #     xpath = text_inputs.replace("visible_text", title)
    #     return len(self.driver.find_elements(By.XPATH, xpath))
    #
    # # ERROR MESSAGES #
    #
    # def verify_input_and_popup_messages(self, data: dict, geo=False):
    #     """
    #     Verify input and popup error messages
    #     :param data: test data
    #     :param geo: True for "GEO Dst Countries to Block" dropdown, otherwise False
    #     """
    #     input_message = data["input_error_message"]
    #     if input_message:
    #         # Get a full title from "error_messages.py" ("Name", "IP/Netmask", etc.)
    #         gui_title = data["gui_title"]
    #         self.verify_input_error_message(gui_title, input_message, geo=geo)
    #
    #     popup_message = data["popup_error_message"]
    #     if popup_message:
    #         self.verify_popup_notification(popup_message, error=True)
    #
    # def verify_input_error_message(self, title, expected_message, geo=False, validation=False):
    #     """
    #     verify_input_error_message
    #     :param title: title of the input
    #     :param expected_message: expected_message
    #     :param geo: True for "GEO Dst Countries to Block" dropdown, otherwise False
    #     :param validation: True for validation_message, otherwise for error message
    #     """
    #     # get expected text
    #     actual_message = self.get_input_error_message(title, plural=isinstance(expected_message, list), geo=geo,
    #                                                   validation=validation)
    #     assert actual_message == expected_message, f"\n  {actual_message=}, but \n{expected_message=}"
    #
    # def get_input_error_message(self, title, plural=False, geo=False, validation=False):
    #     """
    #     Get input error message by text (name of the input). Usually text located on the left side of the input
    #     :param title: title of the input
    #     :param plural: True for multi error messages in one field, otherwise False
    #     :param geo: True for "GEO Dst Countries to Block" dropdown, otherwise False
    #     :param validation: True for validation_message, otherwise for error message
    #     :return: text of an error message
    #     """
    #     xpath = error_message_text.replace("visible_text", title)
    #     if geo:
    #         xpath = xpath.replace("nu-field[1]", "div/nu-field[1]")
    #     if validation:
    #         xpath = xpath.replace("error", "validation-message")
    #     if not self.is_element_present(xpath):
    #         info("There is no an error message")
    #         return ''
    #     return self.get_text_of_elements(xpath) if plural else self.get_text(xpath)
    #
    # # ELEMENT #
    #
    # def get_element(self, xpath):
    #     """
    #     Get element
    #     :param xpath: xpath
    #     :return: Web element (type: selenium.webdriver.remote.webelement.WebElement)
    #     """
    #     return self.driver.find_element(By.XPATH, xpath)
    #

    #
    #
    # def move_to_element_and_verify_tooltip(self, xpath: str, expected_text: str) -> str:
    #     """
    #     Move to a Webelement and verify tooltip text
    #     :param xpath: xpath
    #     :param expected_text: expected tooltip text
    #     :return: error message
    #     """
    #     self.move_to_element(xpath)
    #     return self.verify_text(actual_text=self.get_tooltip(), expected_text=expected_text)
    #

    #
    # def wait_until_loading_sign_disappears_on_dropdown(self):
    #     """
    #     Wait until a loading sign disappears on a dropdown list.
    #     The loading sign is located in the center of the dropdown menu.
    #     """
    #     self.wait_until_element_disappears(loading_dropdown_sign)
    #
    # def wait_until_loading_sign_disappears_on_table(self):
    #     """
    #     Wait until a loading sign disappears on a table.
    #     The loading sign is located in the center of the loading table.
    #     """
    #     self.wait_until_element_disappears(loading_table_sign)
    #

    #
    # def get_text_of_elements(self, xpath) -> list:
    #     """
    #     Get text of web elements
    #     :param xpath: xpath
    #     :return: list of texts
    #     """
    #     return [element.text for element in self.get_elements(xpath)]
    #
    # # GET PARAMETERS OF ELEMENT #
    #
    # def get_classes(self, xpath) -> str:
    #     """
    #     Return classes (str) of the web element
    #     :param xpath: xpath
    #     return: all classes
    #     """
    #     return self.driver.find_element(By.XPATH, xpath).get_attribute("class")
    #
    # def get_theme(self) -> str:
    #     """
    #     Get the UI theme of the page:
    #     :return: Theme name
    #     """
    #     info("get_theme()")
    #     body = self.get_element("//body")
    #     # example of body class="nu-responsive-medium nu-responsive-large nu-light-theme nu-theme-jade nu-nav-style-full-height"
    #     classes = body.get_attribute('className').split()
    #     for class_name in classes:
    #         if re.match("^nu-theme", class_name):
    #             # ex. class_name = "nu-theme-jade"
    #             theme = class_name.split("-")[2]
    #             if theme == "dark":  # Modification for two words compatibility
    #                 return "dark matter"
    #             elif theme in ["neutrino", "graphite", "jade", "mariner", "melongene"]:
    #                 return theme
    #             else:
    #                 raise ValueError(f"{theme=} is invalid.")
    #
    # # RADIOBUTTON #
    #
    # def set_radiobutton(self, title: str, value: str):
    #     """
    #     Set Radiobutton
    #     :param title: title of a radiobutton
    #     :param value: value of a radiobutton
    #     """
    #     debug(f"set_radiobutton('{title}', '{value}')")
    #     radiobutton_desired_value_element = self.get_element(
    #         radiobutton.replace("visible_text", title).replace("value", value))
    #     radiobutton_desired_value_classes = radiobutton_desired_value_element.get_attribute('className')
    #     if "selected" not in radiobutton_desired_value_classes:
    #         radiobutton_desired_value_element.click()
    #
    # def get_radiobutton_value(self, title: str) -> str:
    #     """
    #     Get a Radiobutton selected value
    #     :param title: title of a radiobutton
    #     :return: selected value
    #     """
    #     value = self.get_element(radiobutton_value.replace("visible_text", title)).text
    #     return value
    #
    # def verify_radiobutton_status(self, title: str, value: str):
    #     """
    #     Get status of the Radiobutton
    #     :param title: title of a radiobutton
    #     :param value: expected value of a radiobutton
    #     """
    #     try:
    #         actual_value = self.get_radiobutton_value(title)
    #         if actual_value != value:
    #             return f"\n for Radiobutton '{title}' {actual_value=} but expected value ='{value}'.\n"
    #         return ""
    #     except WebDriverException:
    #         return f"\nRadiobutton {title=} doesn't found"

    # DROPDOWN LIST #

    def get_dropdown_list_value(self, title, position="1", customize_dropdown="") -> str:
        """
        Get the selected value of a dropdown list
        :param title: name of the dropdown list
        :param position: specify the location of dropdown list, when it has several dropdown lists
        :param customize_dropdown: For customized dropdown list without title
        :return: Text of the value of a dropdown list
        """
        xpath = customize_dropdown if customize_dropdown else dropdown_list.replace("visible_text", title).replace(
            "position", position)
        return self.get_text(xpath)

    def open_dropdown_list(self, title, position="1", customize_dropdown=""):
        """
        Open a dropdown list
        :param title: name of the dropdown list
        :param position: specify the location of dropdown list, when it has several dropdown lists
        :param customize_dropdown: For customized dropdown list without title
        """
        if customize_dropdown:
            self.click(customize_dropdown)
        else:
            self.click(dropdown_list.replace("visible_text", title).replace("position", position))
        sleep(1)
        ActionChains(self.driver).send_keys(Keys.DOWN).perform()

    # def set_dropdown_list(self, title: str, value: str, position="1", hard_sleep=0.5, imp_wait=0,
    #                       customize_dropdown=""):
    #     """
    #     Open a dropdown list and set a value
    #     :param title: title of the dropdown list
    #     :param value: value
    #     :param position: specify the location of dropdown list, when it has several dropdown lists
    #     :param hard_sleep: for hard sleep
    #     :param imp_wait: change corresponding setting of the webdriver
    #     :param customize_dropdown: For customized dropdown list without title
    #     """
    #     if value:
    #         self.open_dropdown_list(title, position, customize_dropdown)
    #         info(f"Set Dropdown list value '{value=}'")
    #         # Sometimes Selenium can find the element, but it's not ready to be manipulated, still need to sleep
    #         # TODO: Try to use "wait_until_loading_sign_disappears_on_dropdown()" instead of "hard_sleep"
    #         sleep(hard_sleep)
    #         if imp_wait:
    #             self.driver.implicitly_wait(imp_wait)
    #         if isinstance(value, str):
    #             self.search_in_dropdown_list(title, value)
    #             # TODO: Try to use "wait_until_loading_sign_disappears_on_dropdown()" instead of "hard_sleep"
    #             sleep(hard_sleep)
    #             self.click(active_dropdown_element)
    #         else:
    #             for val in value:
    #                 self.search_in_dropdown_list(title, val)
    #                 self.click(active_dropdown_element)
    #         if imp_wait:
    #             # change back to default
    #             self.driver.implicitly_wait(settings.ui.default_implicit_wait)
    #
    # def search_in_dropdown_list(self, title, value):
    #     """
    #     # TODO: In "set_dropdown_list()" try to use only this method and don't use "search_by_text()"
    #     Search in a dropdown list using the title of the dropdown list in the XPATH.
    #     :param title: title of the dropdown list
    #     :param value: value
    #     """
    #     xpath = dropdown_search_field.replace("visible_text", title)
    #     sleep(0.2)
    #     self.type_text(xpath, value)
    #     sleep(1.5)
    #     self.driver.find_element(By.XPATH, xpath).send_keys(Keys.ENTER)

    # # SLIDE LIST #
    #
    # def close_slide_page(self):
    #     """Close the slide page from the right by clicking 'X'"""
    #     self.click(slide_cross_btn)
    #
    # def get_members_text_and_status_of_slide_list(self) -> [[str, str], ]:
    #     """
    #     Get a text and a status of elements from a slide list
    #     :return: a list of lists with texts and status [["text_1", "selected"], ["text_2", "unselected"], ...]
    #     """
    #     elements = []
    #     for element in self.get_elements(element_of_slide_menu):
    #         # Get text of an element
    #         element_text = element.find_element(By.XPATH, element_of_slide_menu_text).text
    #         element_data = [element_text]
    #         # Check class "Selected" in an element
    #         if "selected" in element.get_attribute('class'):
    #             element_data.append("selected")
    #         else:
    #             element_data.append("unselected")
    #         elements.append(element_data)
    #
    #     return elements
    #
    # # SEARCH #
    #
    #
    # def search_and_click(self, value: str, base_xpath='', suggestion=0, position='1'):
    #     """
    #     Search element in the table through UI using search bar
    #     :param value: text for search
    #     :param base_xpath: base XPATH
    #     :param suggestion: Show search results based on the GUI suggestions. e.g. suggestion=2 for the 2nd suggestion
    #     :param position: Position of Text on the screen (simular to "suggestion")
    #     """
    #     info('search_and_click()')
    #     # TODO: Potentially we can delete "sleep(1)" because method "search_and_click()" mostly uses after "open_page()"
    #     # which alreday has "wait_until_loading_sign_disappears_on_table()"
    #     sleep(1)
    #     self.search_by_text(value=value, base_xpath=base_xpath, suggestion=suggestion)
    #     self.click_by_text(text=value, position=position)
    #
    # def clear_search_field(self):
    #     """Clear the Search field by clicking the 'x'"""
    #     sleep(1)
    #     self.click(clear_search_input_btn)
    #     sleep(1.5)

    # Verification #
    def verify_button_status(self, button_name: str, expected_status: bool) -> str:
        """
        Verify button is enabled
        :param button_name: Visible text on the button
        :param expected_status: Expected button status. e.g. True for enabled, False for disabled.
        :return: error message
        """
        info(f"verify_button_status(), {button_name=}, {expected_status=}")
        try:
            xpath = button.replace("visible_text", button_name) + "/.."
            actual_status = not self.get_element(xpath).get_attribute("disabled")
            if actual_status != expected_status:
                return f"\n{button_name=} is{expected_status * ' NOT'} enabled\n"
            return ""
        except WebDriverException:
            return f"\n{button_name=} doesn't found"

    # def verify_text_field_value(self, title: str, expected_text: str, position="1", not_input=False, plain_string=False,
    #                             plain_number=False, plain_span=False, widget=False, span=False, div=False,
    #                             cus_xpath="", delete_input=False, last_updated=False) -> str:
    #     """
    #     Verify text field value
    #     :param title: title
    #     :param expected_text: expected text field value
    #     :param position: specify the location of dropdown list, when it has several dropdown lists
    #     :param not_input: True for not editable text field, otherwise False
    #     :param plain_string: True for "string-code" field, otherwise False
    #     :param plain_number: True for "number-code" xpath, otherwise False
    #     :param plain_span: True for "span" xpath, otherwise False
    #     :param widget: True for texts in Widgets (Dashboard), otherwise False
    #     :param span: True for texts in "span"(Security Profile), otherwise False
    #     :param div: True for texts in "div"(Instance Version), otherwise False
    #     :param cus_xpath: If provided, verify the customized text element, default is ""
    #     :param delete_input: remove the "input" part in the xpath
    #     :param last_updated: True for the "Last updated at" text, otherwise False
    #     :return: error message
    #     """
    #     info(f"verify_text_field_value(), {title=}, {expected_text=}")
    #     try:
    #         if cus_xpath:
    #             actual_text = self.get_text(cus_xpath)
    #         else:
    #             # We update a general text_input xpath using parameters
    #             # text_input = '(//mn-field-title[contains(text(),"visible_text")]/../following-sibling::nu-field[1]//input)[position]'
    #             xpath = text_input.replace("visible_text", title).replace("position", str(position))
    #             if not_input:
    #                 # For xpath for non-editable text field
    #                 # change "nu-field"
    #                 if widget:
    #                     xpath = xpath.replace("nu-field", "td")
    #                 elif span:
    #                     xpath = xpath.replace("nu-field", "span")
    #                 elif div:
    #                     xpath = xpath.replace("nu-field", "div")
    #
    #                 # change "input"
    #                 if plain_string:
    #                     xpath = xpath.replace("input", "mn-field-content-string-code")
    #                 elif plain_number:
    #                     xpath = xpath.replace("input", "mn-field-content-number-code")
    #                 elif plain_span:
    #                     xpath = xpath.replace("input", "span")
    #                 elif delete_input:  # For a Password field
    #                     xpath = xpath.replace("//input", "")
    #                 elif last_updated:
    #                     xpath = xpath.replace("input",
    #                                           'div[contains(@class,"filter-condition-refresh-block-cache-state")]')
    #                 else:
    #                     xpath = xpath.replace("input", "mn-field-content")
    #                 actual_text = self.get_text(xpath)
    #             else:  # Inputs
    #                 actual_text = self.driver.find_element(By.XPATH, xpath).get_attribute("value")
    #
    #         if actual_text != expected_text:
    #             return f"\n for {title=}\n  {actual_text=}, but\n{expected_text=}\n"
    #         return ""
    #     except WebDriverException:
    #         return f"\nText field {title=} doesn't found"
    #
    # def verify_dropdown_list_value(self, title: str, expected_text: str | list, region=False, entries=False,
    #                                position="1") -> str:
    #     """
    #     Verify dropdown list value
    #     :param title: title
    #     :param expected_text: expected text field value (str or list)
    #     :param region: dropdown list for "Region"
    #     :param entries: True for "Select Entries" dropdown list, otherwise False
    #     :param position: specified xpath
    #     :return: error message
    #     """
    #     info(f"verify_dropdown_list_value(), {title=}, {expected_text=}")
    #     try:
    #         if isinstance(expected_text, str):
    #             xpath = dropdown_list_value.replace("visible_text", title).replace("position",
    #                                                                                "3" if region else position)
    #             actual_text = self.get_text(xpath)
    #         else:
    #             # if expected_text is a list (for "New Policy Set Wizard" with "Outbound Geo Policy")
    #             if entries:
    #                 xpath = dropdown_list_value.replace("visible_text", title).replace(")[position]",
    #                                                                                    "[contains(@class, 'name')])")
    #             else:
    #                 xpath = wizard_dropdown_list_region_elements.replace("visible_text", title)
    #             actual_text = self.get_text_of_elements(xpath)
    #
    #         if actual_text != expected_text:
    #             return f"\n for {title=}\n  {actual_text=}, but\n{expected_text=}\n"
    #         return ""
    #     except WebDriverException:
    #         return f"\nDropdown list {title=} doesn't found"
    #
    # def verify_checkbox_value(self, title: str, expected_status: bool, slide: bool = False, same_level: bool = False,
    #                           extra_text: str = "") -> str:
    #     """
    #     Verify checkbox value
    #     :param title: title
    #     :param expected_status: expected checkbox status
    #     :param slide: "True" for Slide
    #     :param same_level: True for checkbox element which located at the same layer (in html) as its title
    #     :param extra_text: extra text to specify the error message.
    #     :return: error message
    #     """
    #     info(f"verify_checkbox_value(), {title=}, {same_level=}, {expected_status=}")
    #     try:
    #         actual_status = self.is_checkbox_checked(title, slide=slide, same_level=same_level)
    #         if extra_text:
    #             extra_text = "\n  for " + extra_text
    #         if actual_status != expected_status:
    #             return f"{extra_text}\n  for {title=}\n  {actual_status=}, but \n{expected_status=}\n"
    #         return ""
    #     except WebDriverException:
    #         return f"\nCheckbox {title=} doesn't found"
    #
    # def verify_flag(self, title: str, api_data: dict, dropdown: bool = False) -> str:
    #     """
    #     Verify a flag image
    #     :param title: titlexpected_flage
    #     :param api_data: API data
    #     :param dropdown: True for dropdown lists, otherwise False
    #     :return: error message
    #     """
    #     info(f"verify_flag(), {title=}")
    #     try:
    #         xpath = flag_icon.replace("visible_text", title)
    #         if dropdown:
    #             xpath = xpath.replace("position", "2")
    #         else:
    #             xpath = xpath.replace("position", "1")
    #         expected_flag = api_data["region_display_name"]
    #         flag_classes = self.get_classes(xpath)
    #         actual_flag = re.search(r"fi-([a-z]{2})", flag_classes).group(1)
    #         if api_data["cloud_platform"] == "aws":
    #             expected_flag = aws_flags[expected_flag]
    #         else:
    #             expected_flag = azure_flags[expected_flag]
    #         if actual_flag != expected_flag:
    #             return f"\n for {title=}\n {actual_flag=}, but\n{expected_flag=}"
    #         return ""
    #     except WebDriverException:
    #         return f"\nFlag {title=} doesn't found"
    #
    # def verify_icon_status(self, title: str, expected_icon: str, widget=False, div=False) -> str:
    #     """
    #     Verify icon status
    #     :param title: title
    #     :param expected_icon: expected icon status, e.g. "check":“✔”, "times":“×“, "question":”?“, "exclamation":"!",
    #     "clock":"⏱" , "minus":"-", "arrow-circle-up", "arrow-circle-down", "file-invoice" (for a Regular CNF instance
    #     type), "file-invoice-dollar" (for a Price Optimized CNF instance type)
    #     :param widget: True for icons in Widgets (Dashboard), otherwise False
    #     :param div: True to replace "nu-field" with "div", otherwise False
    #     :return: error message
    #     """
    #     info(f"verify_icon_status(), {title=}, {expected_icon=}")
    #     try:
    #         xpath = status_icon.replace("visible_text", title)
    #         # replace "nu-field"
    #         if widget:
    #             xpath = xpath.replace("nu-field", "td")
    #         elif div:
    #             xpath = xpath.replace("nu-field", "div")
    #         actual_icon = self.driver.find_element(By.XPATH, xpath).get_attribute("data-nu-icon")
    #         # ex. actual_icon = "fa-solid__times-circle"
    #         if "arrow" in expected_icon or "file-invoice" in expected_icon:
    #             # "fa-solid__arrow-circle-up"
    #             actual_icon = actual_icon.split("__")[1]  # ex. "arrow-circle-up"
    #         else:
    #             actual_icon = actual_icon.split("__")[1].split("-")[0]  # ex. "times"
    #         if actual_icon != expected_icon:
    #             return f"\n for {title=}\n {actual_icon=}, but \n{expected_icon=}"
    #         return ""
    #     except WebDriverException:
    #         return f"\nIcon {title=} doesn't found"
    #
    # def verify_stage_label_status(self, title: str, active: bool) -> str:
    #     """
    #     Verify stage label status (A tab at the top of the wizard pages that change color when the page is active)
    #     :param title: stage label name
    #     :param active: expected stage label status, True for active
    #     :return: error message
    #     """
    #     info(f"verify_tab_status(): {title=}, {active=}")
    #     try:
    #         xpath = stage_label.replace("visible_text", title)
    #         actual_active_status = "doing" in self.get_classes(xpath)
    #         if actual_active_status != active:
    #             return f"\nStage label '{title}' is{active * ' NOT'} ACTIVE\n"
    #         return ""
    #     except WebDriverException:
    #         return f"\nStage label {title=} doesn't found"
    #
    # def verify_buttons_statuses(self, en: list, ds: list, bottom: bool = False, assertion: bool = False):
    #     """
    #     Verify statuses of the buttons one the top of the table or on the bottom of the page
    #     :param en: names of enabled buttons
    #     :param ds: names of disabled buttons
    #     :param bottom: True for button on the bottom of the page, False for buttons on the top of the page
    #     :param assertion: True to make an assertion inside the method, False to return an error message.
    #     :return: error message
    #     """
    #     error = ""
    #     for en_button in en:
    #         error += self.verify_enabled_action_button(en_button, bottom)
    #     for ds_button in ds:
    #         error += self.verify_disabled_action_button(ds_button, bottom)
    #     if assertion:
    #         assert not error, error
    #     else:
    #         return error
    #
    # def verify_disabled_right_menu_action_button(self, action: str) -> str:
    #     """
    #     Verify a right menu action button is disabled
    #     :param action: action button , e.g. Clone/Edit/Delete
    #     :return: error message
    #     """
    #     info(f"verify_disabled_right_menu_action_button(), {action=}")
    #     try:
    #         xpath = right_menu_btn.replace("visible_text", action) + "/ancestor::nu-menu-item-button"
    #         if "disabled" not in self.get_classes(xpath):
    #             return f'"{action}", '
    #         return ""
    #     except WebDriverException:
    #         return f"\nRight menu action button {action=} doesn't found"
    #
    # def verify_enabled_right_menu_action_button(self, action: str) -> str:
    #     """
    #     Verify right menu action button status (only for right menu action button)
    #     :param action: action button , e.g. Clone/Edit/Delete
    #     :return: error message
    #     """
    #     info(f"verify_enabled_right_menu_action_button(), {action=}")
    #     try:
    #         xpath = right_menu_btn.replace("visible_text", action) + "/ancestor::nu-menu-item-button"
    #         if "disabled" in self.get_classes(xpath):
    #             return f'"{action}", '
    #         return ""
    #     except WebDriverException:
    #         return f"\nRight menu action button {action=} doesn't found"
    #
    # def verify_right_menu_button_statuses(self, en: list, ds: list, text: str = ""):
    #     """
    #     Verify statuses of the right menu buttons
    #     :param en: names of enabled elements in the menu
    #     :param ds: names of disabled elements in the menu
    #     :param text: name of the element in table where we click right button
    #     """
    #     self.right_click_by_text(text)
    #     error = ""
    #     en_error = ""
    #     for enabled in en:
    #         en_error += self.verify_enabled_right_menu_action_button(enabled)
    #     if en_error:
    #         error += "\nfollowing menu items are disabled: " + en_error
    #     ds_error = ""
    #     for disabled in ds:
    #         ds_error += self.verify_disabled_right_menu_action_button(disabled)
    #     if ds_error:
    #         error += "\nfollowing menu items are enabled: " + ds_error
    #     if error:
    #         error = f"\nFor {text} " + error
    #     assert not error, error
