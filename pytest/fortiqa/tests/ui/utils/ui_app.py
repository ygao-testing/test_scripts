"""Base UI class"""
import os
import json
import logging
import platform
from selenium import webdriver
from selenium.common import WebDriverException
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.edge.options import Options as EdgeOptions
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service

from fortiqa.tests.ui.pages.attack_path_top_work_items import TopWorkItemsPage
from fortiqa.tests.ui.pages.aws_cloudtrail import AwsCloudTrailPage
from fortiqa.tests.ui.pages.alerts import AlertsPage
from fortiqa.tests.ui.pages.azure_activity_log import AzureActivityLogPage
from fortiqa.tests.ui.pages.dashboard import DashboardPage
from fortiqa.tests.ui.pages.explorer import ExplorerPage
from fortiqa.tests.ui.pages.gcp_audit_log import GcpAuditLogPage
from fortiqa.tests.ui.pages.settings_onboarding import SettingsOnboardingPage
from fortiqa.tests.ui.pages.vulnerabilities_containers import VulnerabilitiesContainersPage
from fortiqa.tests.ui.pages.vulnerabilities_host import VulnerabilitiesHostPage
from fortiqa.tests.ui.pages.vulnerabilities_new_vuln import VulnerabilitiesNewVulnPage
from fortiqa.tests.ui.pages.workloads_containers import WorkloadsContainersPage
from fortiqa.tests.ui.pages.workloads_hosts import WorkloadsHostsPage
from fortiqa.tests.ui.pages.resource_explorer import ResourceExplorerPage
from fortiqa.tests.ui.pages.resource_inventory import ResourceInventoryPage
from fortiqa.tests.ui.pages.workloads_kubernetes import WorkloadsKubernetesPage
from fortiqa.tests.ui.utils.session_helper import SessionUiHelper
from fortiqa.tests import settings

info = logging.getLogger(__name__).info


class UiApp:
    """UI base class"""

    def __init__(self, url: str):

        if os.environ.get("GITHUB_ACTIONS"):
            # For GitHub Actions
            browser = os.environ.get("BROWSER")
            download_directory = "/home/seluser/Downloads"
            browser_prefs = {
                "download.default_directory": download_directory,
                "download.prompt_for_download": False,
                "download.directory_upgrade": True,
                "safebrowsing.enabled": True
            }
            match browser:
                case "chrome":
                    options = ChromeOptions()
                    options.add_experimental_option("prefs", browser_prefs)
                case "firefox":
                    options = FirefoxOptions()
                    profile = webdriver.FirefoxProfile()
                    profile.set_preference("browser.download.folderList", 2)
                    profile.set_preference("browser.download.dir", download_directory)
                    profile.set_preference("browser.helperApps.neverAsk.saveToDisk",
                                           "application/pdf,application/octet-stream")
                    profile.set_preference("pdfjs.disabled", True)
                    options.profile = profile
                case "edge":
                    options = EdgeOptions()
                    options.add_experimental_option("prefs", browser_prefs)
                case _:
                    raise ValueError(f"Unsupported browser: {browser}")
            options.add_argument("--headless")  # Run in headless mode
            options.add_argument("--window-size=3840,2160")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--ignore-certificate-errors")

            self.driver = webdriver.Remote(command_executor='http://localhost:4444/wd/hub', options=options)
            self.driver.set_page_load_timeout(int(os.environ["SESSION_TIMEOUT"]))

        elif "JENKINS_URL" in os.environ:
            # For Jenkins (Selenoid)
            chrome_options = ChromeOptions()
            chrome_options.add_argument("--ignore-certificate-errors")
            session_name = f"{os.environ['JOB_NAME'][9:]}_{os.environ['BUILD_NUMBER']}"
            capabilities = {
                "browserName": "chrome",
                "browserVersion": "128.0",
                "selenoid:options": {
                    "sessionTimeout": "10m",
                    "screenResolution": "2560x1440x24",
                    "enableVNC": True,
                    "enableVideo": True,
                    "name": session_name,
                    "videoName": session_name + ".mp4"
                }
            }
            chrome_options.capabilities.update(capabilities)

            self.driver = webdriver.Remote(
                command_executor=f"http://{os.environ['SELENOID_AGENT_IP']}:4444/wd/hub",
                options=chrome_options
            )

        else:
            # For local run
            chrome_options = ChromeOptions()
            chrome_options.add_argument("--ignore-certificate-errors")
            os_name = platform.system()
            if os_name == "Linux":
                self.driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
            else:
                self.driver = webdriver.Chrome(options=chrome_options)

        self.driver.maximize_window()
        self.driver.implicitly_wait(settings.ui.default_implicit_wait)

        # Added cookie to the session if exists
        if os.path.exists("cookies.json") and os.environ.get("VALID_COOKIES") == "True":
            # Open page first since Selenium only accepts cookies if the browser is already on the correct domain.
            self.driver.get(f"https://{settings.app.customer['account_name']}.lacework.net/")
            with open("cookies.json", "r") as cookie_file:
                session_cookies = json.load(cookie_file)
            for name, value in session_cookies.items():
                cookie = {
                    "name": name,
                    "value": value,
                    "domain": ".lacework.net",
                    "path": "/",
                    "secure": True,
                    "httpOnly": False
                }
                self.driver.add_cookie(cookie)
            url = f"https://{settings.app.customer['account_name']}.lacework.net/ui/investigation/Dashboard"

        self.driver.get(url)

        self.session = SessionUiHelper(self)
        self.dashboard = DashboardPage(self)
        self.explorer = ExplorerPage(self)
        self.resource_explorer = ResourceExplorerPage(self)
        self.resource_inventory = ResourceInventoryPage(self)
        self.alerts = AlertsPage(self)
        # Cloud logs
        self.aws_cloudtrail = AwsCloudTrailPage(self)
        self.azure_activity_log = AzureActivityLogPage(self)
        self.gcp_audit_log = GcpAuditLogPage(self)
        # Workloads
        self.workloads_hosts = WorkloadsHostsPage(self)
        self.workloads_containers = WorkloadsContainersPage(self)
        self.workloads_kubernetes = WorkloadsKubernetesPage(self)
        # Attack Path
        self.top_work_items = TopWorkItemsPage(self)
        # Vulnerabilities
        self.vulnerabilities_containers = VulnerabilitiesContainersPage(self)
        self.vulnerabilities_host = VulnerabilitiesHostPage(self)
        self.vulnerabilities_new_vuln = VulnerabilitiesNewVulnPage(self)
        # Settings
        self.settings_onboarding = SettingsOnboardingPage(self)

    def leave_only_one_window(self, main_window_handle: str):
        """
        Close all windows except the one main window
        1. Get all open windows.
        2. Close all "documentations" and other not main windows.
        3. Switch to the main window
        """
        for window_handle in self.driver.window_handles:
            if window_handle != main_window_handle:
                self.driver.switch_to.window(window_handle)
                self.driver.close()
        self.driver.switch_to.window(main_window_handle)

    def is_valid(self):
        """Verify the browser is open"""
        try:
            # TODO: Add more verifications
            info(f"current url: '{self.driver.current_url}'")
            return True
        except WebDriverException as exception:
            info(exception)
            return False
