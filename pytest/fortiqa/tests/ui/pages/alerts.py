"""Alerts page"""
import logging
from time import sleep

from fortiqa.tests.ui.utils.base_helper import BaseUiHelper
from fortiqa.tests.ui.utils.webelements_helper import section_data_link
from fortiqa.tests.ui.utils.table_helper import table_header_xpath

info = logging.getLogger(__name__).info

# WebElements
alert_lists_xpath = '//div[@data-testid="alerts-itemlist-content"]//div[contains(@data-testid,"rowid")]'
alert_details_basic_info = '//div[@class="BroadwayPageHeader_broadwayHeaderContentContainer__e5qdn"]'
alert_details_by_title = '//div[contains(text(),"title")]/../div[2]'
alert_investigation = '//span[contains(text(),"Investigation questions")]/../following-sibling::div'
alert_remediation = '//div[contains(text(),"Remediation")]/../following-sibling::div'


class AlertsPage(BaseUiHelper):
    """Alerts page"""

    def verify_alerts_page(self):
        """
        Verify Alerts page:
        1. Open 'Alerts' page.
        2. Get "Overview" data.
        3. Get "Alert Details" data.
            3.1 Verify Alert lists
            3.2 Verify the first alert
                3.2.1 Basic Info. Verify Data consistency between alert list and alert details.
                3.2.2 Details
                3.2.3 Events
                3.2.4 Integrations
                3.2.5 Comments
                3.2.6 Exposure
                3.2.7 Investigation
                3.2.8 Remediation
                3.2.9 Related Alerts
        """
        info("verify_alerts_page()")
        info("1. Open 'Alerts' page.")
        self.open_page('Alerts')
        self.wait_until_loading_sign_disappears()

        info('2. Get "Overview" data.')
        self.click_btn("Reset")
        self.wait_until_loading_sign_disappears()
        total_by_severity = {
            "critical": self.get_text_from_section("Total alerts by severity", "Critical", sub_section=True),
            "high": self.get_text_from_section("Total alerts by severity", "High", sub_section=True),
            "medium": self.get_text_from_section("Total alerts by severity", "Medium", sub_section=True),
            "low": self.get_text_from_section("Total alerts by severity", "Low", sub_section=True),
            "info": self.get_text_from_section("Total alerts by severity", "Info", sub_section=True),
        }
        info(f"{total_by_severity=}")
        # TODO: get "Total alerts over time" chart

        info('3. Get "Alert Details" data.')
        info('3.1 Verify Alert lists')
        alert_list = []
        for alert in self.get_elements(alert_lists_xpath):
            alert_list.append(alert.text.split("\n"))
        info(f"{alert_list=}")

        info('3.2 Verify the first alert')
        first_alert = alert_list[0]
        # Get UI text of the first alert from the alert list: Alert name | ID, status, Alert description, Time window. Tags. Example:
        # first_alert = ['Outbound connection to a new external IP address from application | Alert ID: 198101',
        #                'Status: Open',
        #                'Outbound connection to a new external IP address from application: Application svchost.exe running on host MARY-WIN2019 as user NT AUTHORITY\NETWORK SERVICE made an outbound connection to 23.32.1.230 at TCP port HTTP(80) . This is the first time an outbound connection has been made to this external IP address from this environment',
        #                'Event activity window: 04/21/2025 at 11:00 AM -07:00 to 12:00 PM -07:00',
        #                ' Info', 'Agent', 'Anomaly', 'Application', 'Internet Exposure: Unknown']
        info("Click the first alert and verify all the details.")
        self.click(alert_lists_xpath + "[1]")
        self.wait_until_loading_sign_disappears()

        info('3.2.1 Basic Info. Verify Data consistency between alert list and alert details.')
        basic_info = self.get_text(alert_details_basic_info).split("\n")
        # Get UI text of the basic alert information from the alert details: Alert name, ID, Time window. Tags. Example:
        # basic_info = ['Outbound connection to a new external IP address from application',
        #               'ID: 198101',
        #               'Event activity window: 04/21/2025 at 11:00 AM -07:00 to 12:00 PM -07:00',
        #               ' Info', 'Agent', 'Anomaly', 'Application', 'Internet Exposure: Unknown']
        info('Verify Alert name')
        error = self.verify_text(actual_text=basic_info[0], expected_text=first_alert[0].split("|")[0].strip())
        info('Verify Alert ID')
        error += self.verify_text(actual_text=basic_info[1], expected_text=first_alert[0].split("| Alert ")[1].strip())
        info('Verify Event activity window')
        error += self.verify_text(actual_text=basic_info[2], expected_text=first_alert[3].split(" to ")[0],
                                  partial=True)
        # Sometimes information in alerts list is more than basic_info, need to compare from the back
        info('Verify Alert tags')
        error += self.verify_text(actual_text=basic_info[-4], expected_text=first_alert[-4])
        error += self.verify_text(actual_text=basic_info[-3], expected_text=first_alert[-3])
        error += self.verify_text(actual_text=basic_info[-2], expected_text=first_alert[-2])
        error += self.verify_text(actual_text=basic_info[-1], expected_text=first_alert[-1])
        assert not error, error

        info('3.2.2 Details')
        # Why
        if self.is_element_present(alert_details_by_title.replace("title", "Policy Description")):
            policy_id = self.get_text(alert_details_by_title.replace("title", "Policy ID"))
            info(f"{policy_id=}")
        if self.is_element_present(alert_details_by_title.replace("title", "Policy Description")):
            policy_description = self.get_text(alert_details_by_title.replace("title", "Policy Description"))
            info(f"{policy_description=}")
        # When
        event_activity_window = self.get_text(alert_details_by_title.replace("title", "Event activity window"))
        event_str = first_alert[3].split('window: ')[1].split(' to ')
        date = event_str[0].split(' at ')[0]
        start_time = event_str[0].split(' at ')[1]
        expected_text = f'{date} at {start_time} - {date} at '
        error = self.verify_text(actual_text=event_activity_window, expected_text=expected_text, partial=True)
        assert not error, error
        # What
        # TODO: tabs under "What" is not always the same
        # self.click(table_header_xpath.replace("table_title", "Policy Violations"))
        policy_violations_table = self.get_table_data("What", same_level=True)
        info(f"{policy_violations_table=}")

        info('3.2.3 Events')
        events_tab = table_header_xpath.replace("table_title", "Events")
        if self.get_element(events_tab + "/..").get_attribute("aria-disabled") == "false":
            self.click(events_tab)
            self.wait_until_loading_sign_disappears()
            events_table = self.get_table_data()
            info(f"{events_table=}")

        info('3.2.4 Integrations')
        integrations_tab = table_header_xpath.replace("table_title", "Integrations")
        if self.get_element(integrations_tab + "/..").get_attribute("aria-disabled") == "false":
            self.click(integrations_tab)
            self.wait_until_loading_sign_disappears()
            # TODO: don't have example data

        info('3.2.5 Comments')
        comments_tab = table_header_xpath.replace("table_title", "Comments")
        if self.get_element(comments_tab + "/..").get_attribute("aria-disabled") == "false":
            self.click(comments_tab)
            sleep(1)
            # TODO: don't have example data

        info('3.2.6 Exposure')
        exposure_tab = table_header_xpath.replace("table_title", "Exposure")
        if self.get_element(exposure_tab + "/..").get_attribute("aria-disabled") == "false":
            self.click(exposure_tab)
            # TODO: don't have example data

        info('3.2.7 Investigation')
        investigation_tab = table_header_xpath.replace("table_title", "Investigation")
        if self.get_element(investigation_tab + "/..").get_attribute("aria-disabled") == "false":
            self.click(investigation_tab)
            self.wait_until_loading_sign_disappears()
            investigation_questions = self.get_text(alert_investigation).split("\n")
            info(f"{investigation_questions=}")

        info('3.2.8 Remediation')
        remediation_tab = table_header_xpath.replace("table_title", "Remediation")
        if self.get_element(remediation_tab + "/..").get_attribute("aria-disabled") == "false":
            self.click(remediation_tab)
            self.wait_until_loading_sign_disappears()
            remediation = self.get_text(alert_remediation).split("\n")
            info(f"{remediation=}")
            # TODO: don't have example data

        info('3.2.9 Related Alerts')
        related_alerts_tab = table_header_xpath.replace("table_title", "Related Alerts")
        if self.get_element(related_alerts_tab + "/..").get_attribute("aria-disabled") == "false":
            self.click(related_alerts_tab)
            self.wait_until_loading_sign_disappears()
            related_alerts_table = self.get_table_data()
            info(f"{related_alerts_table=}")

    def verify_alerts_form_dashboard_by_severity(self, severity: str):
        """
        Verify Alerts page by severity and compare with dashboard:
        1. Get 'Alert overview' data from 'Dashboard'.
        2. Go to 'Alerts' page by clicking link in dashboard widget and verify page.
        """
        info("verify_alerts_form_dashboard_by_severity()")
        info("1. Get 'Alert overview' data from 'Dashboard'.")
        self.open_page('Dashboard')
        sleep(2)
        alerts_num_dashboard = self.get_text_from_section("Alert overview", severity)

        info("2. Go to 'Alerts' page by clicking link in dashboard widget and verify page.")
        self.click(section_data_link.replace("section_name", "Alert overview").replace("title_name", severity))
        sleep(4)
        total_by_severity = {
            "critical": self.get_text_from_section("Total alerts by severity", "Critical", sub_section=True),
            "high": self.get_text_from_section("Total alerts by severity", "High", sub_section=True),
            "medium": self.get_text_from_section("Total alerts by severity", "Medium", sub_section=True),
            "low": self.get_text_from_section("Total alerts by severity", "Low", sub_section=True),
            "info": self.get_text_from_section("Total alerts by severity", "Info", sub_section=True),
        }
        # Verify "Alert Overview"
        actual_text = total_by_severity[severity.lower()]
        if "K" in alerts_num_dashboard:
            # Alert is more than 1000:
            actual_text = f"{round(int(actual_text) / 1000, 1)}K"
        error = self.verify_text(actual_text=actual_text, expected_text=alerts_num_dashboard)
        for i in total_by_severity:
            if i != severity.lower():
                error += self.verify_text(actual_text=total_by_severity[i], expected_text="0")
        assert not error, error

        # Verify "Alert Details"
        for alert in self.get_elements(alert_lists_xpath):
            alert_detail = alert.text.split("\n")
            error += self.verify_text(actual_text=alert_detail[4].strip(), expected_text=severity)
        assert not error, error
