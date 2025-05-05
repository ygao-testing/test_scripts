"""Vulnerabilities New Vulnerabilities page"""
import logging
import os
import csv
import io
from time import sleep

from fortiqa.tests.ui.data.long_text import vulnerabilities_tooltips
from fortiqa.tests.ui.utils.base_helper import BaseUiHelper
from fortiqa.tests.ui.utils.session_helper import SessionUiHelper
from fortiqa.tests.ui.utils.work_with_files import Files
from fortiqa.tests.ui.utils.webelements_helper import section_title, button, pagination_xpath, notification

info = logging.getLogger(__name__).info
debug = logging.getLogger(__name__).debug

# Xpaths #
# General
legends_by_subsection = section_title + '/../../..//ul[contains(@class, "legend")]'
legend_data_by_subsection = section_title + '/../../following-sibling::div//div[@data-testid="legend-legend_name"]'
# Top Items
tab_in_section = '//div[@role="tab"]//div[text()="tab_name"]'
expand_tab_list_btn = '//button[@aria-haspopup="listbox"]'
expanded_tab = '//li[contains(@id,"rc-tabs")]//div[text()="tab_name"]'
empty_table = '//p[@class="ant-empty-description"]'
# Latest status
pie_chart_by_subsection = section_title + '/../../..//div[contains(@data-testid,"donut-widget")]'
# Trends by resource groups
resource_groups_by_section = section_title + '/../../..//div[contains(@style,"line-height: 18px; letter-spacing: 0.004em;")]'
previous_page_btn_by_subsection = section_title + '/../../..//button[@data-testid="previous-page"]'
next_page_btn_by_subsection = section_title + '/../../..//button[@data-testid="next-page"]'
chart_by_resource_group = section_title + '/../../..//div[text()="resource_group"]/..//div[@class="trellis-trend-sparkline-chart-container"]'
empty_chart_by_resource_group = section_title + '/../../..//div[text()="resource_group"]/..//div[@class="trellis-trend-sparkline-empty "]'

subsections_by_section = {
    "Total status over time": ["Comparison of host vulnerabilities", "Comparison of container vulnerabilities",
                               "Total at risk host vulnerabilities", "Total at risk container vulnerabilities"],
    "Trend": ["Host vulnerabilities over time", "Container vulnerabilities over time"],
    "Top Items": ["Top vulnerable container images", "Top vulnerable hosts", "Top vulnerabilities by impacted hosts",
                  "Top vulnerabilities by impacted images", "Top fixable packages in containers",
                  "Top fixable packages in hosts", "Most recent vulnerable hosts",
                  "Most recent vulnerable container images"],
    "Latest status": ["Unscanned images with active containers", "Latest at risk container images",
                      "Latest at risk hosts", "Host coverage type", "OS EOL dates"],
    "Trends by resource groups": ["Host vulnerabilities at risk", "Container vulnerabilities at risk"],
}

default_all_resource_groups_by_type = ["All AWS Resources", "All Azure Resources", "All Container Resources",
                                       "All GCP Resources", "All Kubernetes Resources", "All Machines",
                                       "All OCI Resources"]


class VulnerabilitiesNewVulnPage(BaseUiHelper):
    """Vulnerabilities New Vulnerabilities page"""

    # Overview #
    def switch_new_legacy_vulnerabilities(self, legacy: str):
        """
        Switch between New and Legacy Vulnerabilities page
        1. Open 'Vulnerabilities New Vuln' page.
        2. Switch to legacy Vulnerabilities page.
        3. Switch to new Vulnerabilities page.
        :param legacy: Legacy page name. e.g. "Hosts", "Container images"
        """
        info("1. Open 'Vulnerabilities New Vuln' page.")
        self.open_page("Vulnerabilities Vulnerabilities")

        info("2. Switch to legacy Vulnerabilities page.")
        self.click_tab("Explore", sub_tab=legacy)
        self.click_by_text("Switch to legacy vulnerability page")
        sleep(1)
        self.wait_until_loading_sign_disappears()
        match legacy:
            case "Hosts":
                self.click_tab("Host")
            case "Container images":
                self.click_tab("Image ID")
            case _:
                raise ValueError(f"{legacy=} not recognized")

        info("3. Switch to new Vulnerabilities page.")
        self.click_by_text("Switch to new vulnerability pages")
        self.wait_until_loading_sign_disappears()
        self.click_tab("Top items")
        self.click_tab("Overview")

    def verify_overview_tab(self):
        """
        Verify Vulnerabilities new Vuln / Overview tab
        1. Open 'Vulnerabilities New Vuln' page
        2. Verify tab
        3.1. Verify 'Total status over time' section
        3.2. Verify 'Trend' section
        3.3. Verify 'Latest status' section
        3.4. Verify 'Trends by resource groups' section
        """
        info("1. Open 'Vulnerabilities New Vuln' page.")
        self.open_page("Vulnerabilities Vulnerabilities")

        info("2. Verify tab")
        self.click_tab("Top items")  # Won't be able to verify URL if don't switch selected tab
        self.click_tab("Overview")
        self.wait_until_loading_sign_disappears()

        info("3.1. Verify 'Total status over time' section")
        self.verify_tooltips_by_section("Total status over time")
        # Verify data for past 1 week
        self.switch_data_window("Total status over time", "1 week")
        for title in subsections_by_section["Total status over time"]:
            self.verify_legend_data_by_subsection(title, ["Critical", "High", "Medium", "Others"])
        # Verify data for past 30 days
        self.switch_data_window("Total status over time", "30 days")
        for title in subsections_by_section["Total status over time"]:
            self.verify_legend_data_by_subsection(title, ["Critical", "High", "Medium", "Others"])

        info("3.2. Verify 'Trend' section")
        self.verify_tooltips_by_section("Trend")
        # Verify data for past 1 week
        self.switch_data_window("Trend", "1 week")
        for title in subsections_by_section["Trend"]:
            self.verify_legend_data_by_subsection(title, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                                                  legend_only=True)
        # Verify data for past 30 days
        self.switch_data_window("Trend", "30 days")
        for title in subsections_by_section["Trend"]:
            self.verify_legend_data_by_subsection(title, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                                                  legend_only=True)

        info("3.3. Verify 'Latest status' section")
        self.verify_tooltips_by_section("Latest status")
        self.verify_legend_data_by_subsection("Unscanned images with active containers",
                                              ["Error", "Partial", "Unscanned"], pie_chart=True)
        self.verify_legend_data_by_subsection("Latest at risk container images",
                                              ["Critical", "High", "Medium", "Low", "Info"], pie_chart=True)
        self.verify_legend_data_by_subsection("Latest at risk hosts", ["Critical", "High", "Medium", "Low", "Info"],
                                              pie_chart=True)
        self.verify_legend_data_by_subsection("Host coverage type",
                                              ["Agent only", "Agentless only", "Agent and Agentless"], pie_chart=True)
        self.verify_legend_data_by_subsection("OS EOL dates", [], pie_chart=True)

        info("3.4. Verify 'Trends by resource groups' section")
        self.verify_tooltips_by_section("Trends by resource groups")
        # Verify data for past 1 week
        self.switch_data_window("Trends by resource groups", "1 week")
        for title in subsections_by_section["Trends by resource groups"]:
            self.verify_chart_by_resource_group(title)
        # Verify data for past 30 days
        self.switch_data_window("Trends by resource groups", "30 days")
        for title in subsections_by_section["Trends by resource groups"]:
            self.verify_chart_by_resource_group(title)

    def verify_top_items_tab(self, widget: str):
        """
        Verify Top Items data and download table
        1. Open 'Vulnerabilities New Vuln' page.
        2. Verify Top Items data and download table
            2.1 Verify tooltips
            2.2 Verify table data
            2.3. Verify full Top Items list on 'Explore' page
        # 2.2 Download table and verify
        :param widget: Name of the widget title
        """
        info("1. Open 'Vulnerabilities New Vuln' page")
        self.open_page("Vulnerabilities Vulnerabilities")
        self.click_tab("Top items")
        self.wait_until_loading_sign_disappears()

        info("2. Verify Top Items data and download table")
        # All widget should already be added in the default view manually, will return error if any widget is missing
        assert self.is_element_present(section_title.replace("section_name", widget)), f"{widget=} is not displayed."
        info("2.1 Verify tooltips")
        self.verify_tooltips_by_section(widget, single_section=True)
        info("2.2 Verify table data")
        empty_top_item = False
        gui_table = self.get_table_data(table_title=widget, three_level=True)
        info(f"{gui_table=}")
        if not gui_table:
            empty_result_xpath = f'{section_title.replace("section_name", widget)}/../../..{empty_table}'
            assert self.is_element_present(empty_result_xpath), f"Table for {widget=} is not loaded."
            error = self.verify_text(xpath=empty_result_xpath, expected_text="No results found")
            assert not error, error
            info(f"No results found in {widget=}")
            empty_top_item = True

        info("2.3. Verify full Top Items list on 'Explore' page")
        self.click_btn("View more", base_xpath=f'{section_title.replace("section_name", widget)}/../../..')
        self.wait_until_loading_sign_disappears()
        # Hide top
        if self.is_element_present(button.replace("visible_text", "Hide")):
            self.click_btn("Hide")
        full_gui_table = self.get_the_two_sections_table()
        info(f"{full_gui_table=}")
        if empty_top_item:
            assert self.is_element_present(empty_table), f"Full table for {widget=} in the Explore page is not loaded."
            error = self.verify_text(xpath=empty_table, expected_text="No results found")
            assert not error, error
            self.compare_actual_and_expected_tables(expected_table=[], actual_table=full_gui_table,
                                                    two_sections_table=True)
            return

        info("2.2 Download table and verify")
        if not os.environ.get("GITHUB_ACTIONS"):
            total_columns = self.get_text(pagination_xpath).split("of ")[1]
            # Download file
            self.click_download_btn()
            self.click_by_text("Table CSV")
            sleep(1)
            self.click_btn("Start the download")
            self.wait_until_element_appears(notification, timeout=40)
            self.click_by_text("Download now", base_xpath=notification)
            sleep(10)
            matched_file = Files().verify_file(prefix="", suffix="csv", driver=self.driver)
            SessionUiHelper(self).close_notification()
            # Verify downloaded file
            if "JENKINS_URL" in os.environ:
                csv_table = list(csv.reader(io.StringIO(matched_file.text)))
            else:
                with open(matched_file, 'r') as csv_file:
                    csv_table = list(csv.reader(csv_file))
            if "+" not in total_columns:
                self.compare_row_num(actual_table=csv_table, expected_rows=int(total_columns) + 1)

    def verify_tooltips_by_section(self, section_name: str, switch_tab: bool = False, single_section: bool = False):
        """
        Verify tooltip by each title in the specified section
        :param section_name: Name of the section
        :param switch_tab: True for need to open each tab before tooltip shows up
        :param single_section: True for there's no subsection in the section
        """
        info(f"verify_tooltips_by_section(), {section_name=}")
        error = ""
        section = section_title.replace("section_name", section_name)
        self.move_viewport_to_element(section)
        self.wait_until_loading_sign_disappears()
        if single_section:
            tooltip_text = self.get_tooltip_by_title(section_name)
            self.move_to_element(section)  # Move mouse away in order to close tooltip
            error += self.verify_text(actual_text=tooltip_text, expected_text=vulnerabilities_tooltips[section_name])
        else:
            for title in subsections_by_section[section_name]:
                if switch_tab:
                    self.switch_tab(title)
                tooltip_text = self.get_tooltip_by_title(title)
                self.move_to_element(section)  # Move mouse away in order to close tooltip
                error += self.verify_text(actual_text=tooltip_text, expected_text=vulnerabilities_tooltips[title])
        assert not error, error

    def switch_tab(self, tab: str):
        """
        Switch to specified Tab when there are multiple tabs in the section
        :param tab: Tab name
        """
        info(f"switch_tab(), {tab=}")
        self.move_to_element(expand_tab_list_btn)
        if self.is_element_present(expanded_tab.replace("tab_name", tab)):
            self.click(expanded_tab.replace("tab_name", tab))
        else:
            self.click(tab_in_section.replace("tab_name", tab))
        self.wait_until_loading_sign_disappears()

    def switch_data_window(self, section_name: str, window: str):
        """
        Switch data time window
        :param section_name: Name of the section
        :param window: Time window for the displayed data. e.g. "1 week", "30 days"
        """
        info(f"switch_data_window(),{section_name=}, {window=}")
        section_xpath = section_title.replace("section_name", section_name)
        self.click(section_xpath + '/../label[@data-testid="trellis-select-label-wrapper"]')
        self.click(section_xpath + f'/..//span[text()="{window}"]')
        self.wait_until_loading_sign_disappears()

    def verify_legend_data_by_subsection(self, subsection_name: str, legends: list, legend_only: bool = False,
                                         pie_chart: bool = False):
        """
        Get data for the specified subsection by each legend
        :param subsection_name: Name of the title
        :param legends: Legends in the subsection
        :param legend_only: True for verify the text for the legends only
        :param pie_chart: Pie chart in the subsection
        """
        info(f"verify_legend_data_by_subsection(), {subsection_name=}")
        if legend_only:
            actual_legends = self.get_text(legends_by_subsection.replace("section_name", subsection_name)).split("\n")
            assert actual_legends == legends, f"Graph data in the {subsection_name=} is not loaded."
        elif pie_chart:
            assert self.is_element_present(pie_chart_by_subsection.replace("section_name", subsection_name)), \
                f"Pie chart in the {subsection_name=} is not loaded."
        elif legends:
            section_legends = legend_data_by_subsection.replace("section_name", subsection_name)
            legends_data = {}
            for legend in legends:
                legends_data[legend.lower()] = \
                    self.get_text(section_legends.replace("legend_name", legend)).split("\n")[0]
            assert legends_data, f"Data in the {subsection_name=} is not loaded."
            info(f"Data in the {subsection_name=}: {legends_data=}")

    def verify_chart_by_resource_group(self, subsection_name: str):
        """
         Verify chart by each resource group in the specified section
        :param subsection_name: Name of the title
        """
        info(f"verify_chart_by_resource_group(), {subsection_name=}")
        # Return to the first page
        attempts = 0
        while "1 - 3 of" not in self.get_text(
                f'{section_title.replace("section_name", subsection_name)}/../../..{pagination_xpath}'):
            self.click(previous_page_btn_by_subsection.replace("section_name", subsection_name))
            self.wait_until_loading_sign_disappears()
            attempts += 1
            if attempts > 5:
                raise Exception(f"Failed to return resource group chart list to the first page for {subsection_name=}")
        # Verify chart data
        error = ""
        for _ in range(2):
            resource_groups = self.get_text_from_several_elements(
                resource_groups_by_section.replace("section_name", subsection_name)).split("\n")
            for resource_group in resource_groups:
                chart_displayed = (self.is_element_present(
                    chart_by_resource_group.replace("section_name", subsection_name).replace("resource_group",
                                                                                             resource_group)) or
                                   self.get_text(
                                       empty_chart_by_resource_group.replace("section_name", subsection_name).replace(
                                           "resource_group",
                                           resource_group)) == "No data found for this resource group")
                if not chart_displayed:
                    error += f"Chart data for {resource_group=} is not loaded."
            self.click(next_page_btn_by_subsection.replace("section_name", subsection_name))
            self.wait_until_loading_sign_disappears()
        assert not error, error
