"""Vulnerabilities Host page"""
import logging
import math
import csv
import io
import os
from datetime import datetime, timedelta, timezone
from time import sleep
from selenium.webdriver.common.by import By

from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.host_vulnerabilities_helper import HostVulnerabilitiesHelper
from fortiqa.tests.ui.utils.base_helper import BaseUiHelper
from fortiqa.tests.ui.utils.session_helper import SessionUiHelper
from fortiqa.tests.ui.utils.work_with_files import Files
from fortiqa.tests.ui.utils.webelements_helper import vuln_host_section_text, notification

info = logging.getLogger(__name__).info

vulnerabilities_section = '//div[@data-testid="vulnerability-list-view-loaded"]'
vulnerabilities_list_items = '//div[@data-testid="vulnerability-list-item"]'
empty_vulnerabilities_info = '//div[text()="Vulnerabilities"]/ancestor::div[@class="trellis-itemlist"]//p[@class="ant-empty-description"]'
total_vul_num_xpath = vulnerabilities_section + '//span[@class="trellis-pagination-label"]'


class VulnerabilitiesHostPage(BaseUiHelper):
    """Vulnerabilities Host page"""

    def verify_host_page(self, api_v1_client):
        """Verify Vulnerabilities Host / Host page"""
        info("1. Open 'Vulnerabilities Legacy' page.")
        self.open_page("Vulnerabilities Host")

        info("2. Host")
        self.click_tab("Host")
        self.click_btn("Reset")
        self.wait_until_loading_sign_disappears()

        info("2.1. Verify 'Dashboard' section")
        query_card_api = QueryCard(api_v1_client)
        current_time = datetime.now(timezone.utc) if "JENKINS_URL" in os.environ else datetime.now()
        one_day_ago = current_time - timedelta(days=1)
        payload = {
            "ParamInfo": {
                "StartTimeRange": int(one_day_ago.timestamp()),
                "EndTimeRange": int(current_time.timestamp()),
                "EnableEvalDetailsMView": True
            },
            "Filters": {
                "HostVuln_Filters.HOST_TYPE": [{"value": "Online", "filterGroup": "eq"},
                                               {"value": "Launched", "filterGroup": "eq"}]
            }
        }
        vuln_summary_api = query_card_api.exec_query_card(card_name="HostVuln_StatsSummaryAll", payload=payload).json()[
            "data"][0]
        error = ""
        dashboard_section = vuln_host_section_text.replace("section_name", "Dashboard")
        error += self.verify_text(dashboard_section.replace("element_name", "Scanned hosts"),
                                  vuln_summary_api["NUM_EVAL_SUCCESSFUL_HOSTS"])
        mttr = vuln_summary_api["MTTR"] if vuln_summary_api["MTTR"] else "N/A"
        error += self.verify_text(dashboard_section.replace("element_name", "MTTR"), mttr)
        error += self.verify_text(dashboard_section.replace("element_name", "Hosts with critical or high severities"
                                                            ), vuln_summary_api["NUM_CRITICAL_HIGH_SEVERITY_HOSTS"])
        error += self.verify_text(dashboard_section.replace("element_name", "Hosts monitored by Code Aware Agent (CAA)"
                                                            ),
                                  f"{vuln_summary_api['NUM_CAA_ENABLED_HOSTS']}\n/ Total {vuln_summary_api['NUM_EVAL_SUCCESSFUL_HOSTS']}")
        assert not error, error

        info("2.2. Verify 'Vulnerabilities' section")
        # Get GUI list
        vulnerabilities = self.get_elements(vulnerabilities_list_items)
        if not vulnerabilities:
            error = self.verify_text(empty_vulnerabilities_info, "No data\nNo data to display")
            assert not error, error
        vulnerabilities_gui_table = []
        for vuln in vulnerabilities:
            table_line = []
            sections = vuln.find_elements(By.XPATH, "div")
            for index, section in enumerate(sections):
                # Skip verifying tags since it's hard to predict the expected value
                table_line.append(section.text.split("\n")[0] if index == 0 else section.text)
            vulnerabilities_gui_table.append(table_line)
        info(f"{vulnerabilities_gui_table=}")

        # Get API list
        vuln_helper = HostVulnerabilitiesHelper(api_v1_client)
        vulnerabilities_api_table = vuln_helper.list_all_vulnerability_hosts()
        converted_api_table = self.convert_vulnerable_hosts_api_data_into_gui(vulnerabilities_api_table)
        expected_table = []
        for gui in vulnerabilities_gui_table:
            for api in converted_api_table:
                if gui[0] == api[0]:
                    expected_table.append(api)
                    break
        if not vulnerabilities:
            return  # Skip the following verification since Download button will be disabled if no data

        if not os.environ.get("GITHUB_ACTIONS"):
            total_vul_num = self.get_text(total_vul_num_xpath).split("of ")[1]
            # 1. Download Simplified CSV
            self.click_download_btn(base_xpath=vulnerabilities_section)
            self.click_by_text("Simplified CSV")
            sleep(1)
            self.click_btn("Start the download")
            self.wait_until_element_appears(notification, timeout=90)
            self.click_by_text("Download now", base_xpath=notification)
            sleep(20)
            files = Files()
            matched_file = files.verify_file(prefix="Host Vulnerabilities Simplified CSV", suffix="csv",
                                             driver=self.driver)
            info("Downloaded Simplified Host Vulnerabilities.")
            session_helper = SessionUiHelper(self)
            session_helper.close_notification()

            # Open the downloaded CSV file and verify content
            if "JENKINS_URL" in os.environ:
                csv_table = list(csv.reader(io.StringIO(matched_file.text)))
            else:
                with open(matched_file, 'r') as csv_file:
                    csv_table = list(csv.reader(csv_file))
            expected_header = ['LAST_EVAL_TIME', 'INTERNET_EXPOSURE_LAST_UPDATED', 'MID', 'EVAL_GUID', 'EVAL_CTX',
                               'COVERAGE_TYPES', 'CAA_ENABLED', 'COLLECTOR_TYPE', 'HOST_NAME', 'EXTERNAL_IP',
                               'INTERNAL_IP', 'MACHINE_TAGS', 'ACCOUNT', 'HOST_TYPE', 'NUM_VULNERABILITIES',
                               'NUM_FIXES', 'NUM_EXCEPTION', 'NUM_VULNERABILITIES_SEVERITY_1',
                               'NUM_VULNERABILITIES_SEVERITY_2',
                               'NUM_VULNERABILITIES_SEVERITY_3', 'NUM_VULNERABILITIES_SEVERITY_4',
                               'NUM_VULNERABILITIES_SEVERITY_5', 'NUM_VULNERABILITIES_FIX_SEVERITY_1',
                               'NUM_VULNERABILITIES_FIX_SEVERITY_2', 'NUM_VULNERABILITIES_FIX_SEVERITY_3',
                               'NUM_VULNERABILITIES_FIX_SEVERITY_4', 'NUM_VULNERABILITIES_FIX_SEVERITY_5',
                               'NUM_VULNERABILITIES_EXCEPTION_SEVERITY_1', 'NUM_VULNERABILITIES_EXCEPTION_SEVERITY_2',
                               'NUM_VULNERABILITIES_EXCEPTION_SEVERITY_3', 'NUM_VULNERABILITIES_EXCEPTION_SEVERITY_4',
                               'NUM_VULNERABILITIES_EXCEPTION_SEVERITY_5',
                               'NUM_VULNERABILITIES_EXCEPTION_FIX_SEVERITY_1',
                               'NUM_VULNERABILITIES_EXCEPTION_FIX_SEVERITY_2',
                               'NUM_VULNERABILITIES_EXCEPTION_FIX_SEVERITY_3',
                               'NUM_VULNERABILITIES_EXCEPTION_FIX_SEVERITY_4',
                               'NUM_VULNERABILITIES_EXCEPTION_FIX_SEVERITY_5', 'UP_TIME_MINS', 'EVAL_STATUS',
                               'EVAL_MSG',
                               'OS_NAMESPACE', 'EOL_DATE', 'RISK_SCORE', 'RISK_INFO', 'PUBLIC_FACING',
                               'INTERNET_EXPOSURE',
                               'OS', 'UPDATES_DISABLED', 'REBOOT_REQUIRED', 'OS_OUT_OF_DATE']
            self.compare_column_headers_and_row_num(expected_header=[expected_header],
                                                    expected_rows=int(total_vul_num) + 1,
                                                    actual_table=csv_table)
            # Verify vulnerabilities host names
            all_csv_vul_host_name = set()
            for row in csv_table[1:]:
                all_csv_vul_host_name.add(row[8])
            for vuln in vulnerabilities_gui_table:
                host_name = vuln[0][10:]
                if host_name not in all_csv_vul_host_name:
                    error += f"\nHost name {host_name} is not listed in the downloaded file."
            assert not error, error

            # 2. Download Detailed CSV
            self.click_download_btn(base_xpath=vulnerabilities_section)
            self.click_by_text("Detailed CSV")
            sleep(1)
            self.click_btn("Start the download")
            self.wait_until_element_appears(notification, timeout=40)
            self.click_by_text("Download now", base_xpath=notification)
            sleep(40)
            matched_file = files.verify_file(prefix="Host Vulnerability Detailed CSV", suffix="csv", driver=self.driver)
            info("Downloaded Detailed Host Vulnerabilities.")
            session_helper.close_notification()
            csv.field_size_limit(300000 * 1024)
            if "JENKINS_URL" in os.environ:
                csv_table = list(csv.reader(io.StringIO(matched_file.text)))
            else:
                with open(matched_file, 'r') as csv_file:
                    csv_table = list(csv.reader(csv_file))
            expected_header = ['START_TIME', 'END_TIME', 'VULN_ID', 'MID', 'EVAL_GUID', 'PACKAGE_NAMESPACE',
                               'PACKAGE_NAME', 'PACKAGE_PATH', 'PACKAGE_ACTIVE', 'VERSION_INSTALLED', 'MACHINE_TAGS',
                               'EVAL_CTX', 'FEATURE_KEY', 'SEVERITY', 'FIX_INFO', 'STATUS', 'FIXED_VERSION',
                               'FIX_AVAILABLE', 'CVE_PROPS', 'PROPS', 'COVERAGE_TYPES', 'RISK_SCORE',
                               'INTERNET_EXPOSURE', 'EVAL_STATUS', 'HOST_TYPE', 'INTERNET_EXPOSURE_LAST_UPDATED',
                               'UP_TIME_MINS', 'COLLECTOR_TYPE', 'HOSTNAME', 'EXTERNAL_IP', 'INTERNAL_IP', 'ACCOUNT',
                               'EOL_DATE']
            self.compare_column_headers_and_row_num(expected_header=[expected_header], actual_table=csv_table)

        self.click_tab("CVE", timeout=40)
        self.click_tab("AMI ID")
        self.click_tab("Account")
        self.click_tab("Zone")
        self.click_tab("Package Name", timeout=40)
        self.click_tab("Application (Windows)")
        self.click_tab("Package Namespace")

    @staticmethod
    def convert_vulnerable_hosts_api_data_into_gui(api_data: list) -> list:
        r"""
        Convert API data from the './card/query/HostVuln_HostsSummaryAll_MV_NamedSet' endpoint into GUI table.
        :param api_data: api data
        :return converted_gui_data: list of converted GUI data
        example: converted_gui_data = [
            [
                'Hostname: ip-10-0-0-112.us-east-2.compute.internal',
                'Uptime:\n66 D : 23 H : 36 M',
                'Host Risk\n10\n/10',
                '442 CVEs\n0\ncritical\n12\nhigh\n430\nother']
        ]
        """
        info(f"convert_top_vulnerable_hosts_api_data_into_gui(), {api_data=}")
        converted_gui_data = []
        for host in api_data:
            uptime_mins = int(host["UP_TIME_MINS"])
            days = uptime_mins // (24 * 60)
            hours = (uptime_mins % (24 * 60)) // 60
            mins = uptime_mins % 60
            parts = []
            if days:
                parts.append(f"{days} D")
            if hours:
                parts.append(f"{hours} H")
            if mins:
                # Potentially minutes on the UI could be 1 min different form API
                parts.append(f"{mins} M")
            uptime = " : ".join(parts)
            risk_score = math.ceil(0 if host["RISK_SCORE"] is None else float(host["RISK_SCORE"]))
            num_fixs = host["NUM_FIXES"]
            num_critical = host["NUM_VULNERABILITIES_FIX_SEVERITY_1"]
            num_high = host["NUM_VULNERABILITIES_FIX_SEVERITY_2"]
            num_other = str(
                int(host["NUM_VULNERABILITIES_FIX_SEVERITY_3"]) + int(
                    host["NUM_VULNERABILITIES_FIX_SEVERITY_4"]) + int(
                    host["NUM_VULNERABILITIES_FIX_SEVERITY_5"]))
            converted_gui_data.append(
                [f'Hostname: {host["HOST_NAME"]}', f'Uptime:\n{uptime}', f'Host Risk\n{risk_score}\n/10',
                 f'{num_fixs} CVEs\n{num_critical}\ncritical\n{num_high}\nhigh\n{num_other}\nother'])
        return converted_gui_data
