"""Table Helper class"""
import json
import logging

from selenium.webdriver.common.by import By

from fortiqa.tests import settings
from fortiqa.tests.ui.utils.webelements_helper import WebElementsHelper

# Table with Title
table_with_title_rows = '//*[contains(text(),"table_title")]/ancestor::div[contains(@style,"display: flex; align-items: center")]//following-sibling::div//div[contains(@class,"ag-body ag-layout")]//div[@role="row"]'
# Some tables are collapse when you click on the top of them (like on the "Dashboard" page)
collapsible_table_with_title_rows = '//div[text()="table_title"]//ancestor::div[contains(@class, "trellis-collapse-skeleton")]//div[@role="row" and @row-index]'
# Table without Title
left_container_rows = '//div[@class="ag-pinned-left-cols-container"]//div[@role="row" and contains(@class,"ag-row-position-absolute")]'
center_container_rows = '//div[@class="ag-center-cols-container"]//div[@role="row" and contains(@class,"ag-row-position-absolute")]'

# Table header
table_header_xpath = '//*[@role="heading" and contains(., "table_title")]'

# Table loading sign
table_spin = '//div[@role="heading" and text()="table_title"]/../../following-sibling::div//div[@class="ant-spin ant-spin-spinning"]'

info = logging.getLogger(__name__).info


class TableHelper(WebElementsHelper):
    """Table helper"""

    def get_table_data(self, table_title="", rows_xpath="", collapsible_table=False, same_level=False,
                       three_level=False) -> list:
        """
        Get table data
        :param table_title: The title of the table.
        :param rows_xpath: rows xpath
        :param collapsible_table: "True" if the table is collapse when you click on the top of it (like the "Dashboard" page tables)
        :param same_level: True for title is the same level as table
        :param three_level: True for title has three level difference with row in xpath
        :return: the table data
        """
        # TODO: Some tables are very wide, and we must scroll right to get from all columns.
        # Update method to scroll right (use Shift + scroll down on a mouse or JavaScript; zoom doesn't work) and get
        # full data if we have a horizontal scrolling bar. We probably need to get the data not row by row but column
        # by column because the number of rows is less important than the number of columns (we will only scroll right,
        # but not scroll down). We can get only the top visible lines of the table.
        # TASK: https://dops-git.fortinet-us.com/cloudservices/fcsqa/-/issues/898

        info("get_table_data()")
        if not rows_xpath:
            if table_title:
                if collapsible_table:
                    rows_xpath = collapsible_table_with_title_rows.replace("table_title", table_title)
                else:
                    rows_xpath = table_with_title_rows.replace("table_title", table_title)
                if same_level:
                    rows_xpath = rows_xpath.replace(
                        '/ancestor::div[contains(@style,"display: flex; align-items: center")]', '')
                if three_level:
                    rows_xpath = rows_xpath.replace(
                        '/ancestor::div[contains(@style,"display: flex; align-items: center")]//following-sibling::div',
                        '/../../..')
            else:
                rows_xpath = table_with_title_rows.split('following-sibling::div')[1]
        self.driver.implicitly_wait(2)
        rows = self.get_elements(rows_xpath)

        table_data = []
        for row in rows:
            row_data = []
            columns = row.find_elements(By.XPATH, "div")
            for column in columns:
                row_data.append(column.text)
            table_data.append(row_data)
        self.driver.implicitly_wait(settings.ui.default_implicit_wait)
        return table_data

    def get_the_two_sections_table(self) -> list:
        """
        Sometimes, the table has two parts: the Left and Center parts. The Left part is stuck, but the Center part has
        a horizontal scroll bar. Most tables don't have the stuck part and have only Center part.
        :return: the table data
        """
        left_container_data = self.get_table_data(rows_xpath=left_container_rows)
        center_container_data = self.get_table_data(rows_xpath=center_container_rows)
        if not left_container_data:
            return center_container_data
        full_table_data = []
        for x in range(len(center_container_data)):
            full_table_data.append(left_container_data[x] + center_container_data[x])
        return full_table_data

    def move_to_table_and_get_data(self, table_title: str = "", move_down=False, collapsible_table=False) -> list:
        """
        Move to the table and get the table data.
        :param table_title: Table's title
        :param move_down: move down a little bit for table titles with tag "a" (an anchor with a hyperlink)
        :param collapsible_table: "True" if the table is collapse when you click on the top of it (like the "Dashboard" page tables)
        :return: the table data
        """
        xpath = table_header_xpath.replace("table_title", table_title)
        # Sometimes, the table title has the tag "a" (an anchor with a hyperlink), and we cannot click on it before
        # scrolling down the page. We need to move to the title, next move down a little bit, click, and scroll down.
        self.move_to_element_and_scroll_down(xpath, move_down=move_down)
        self.wait_until_element_disappears(table_spin.replace("table_title", table_title))
        return self.get_table_data(table_title=table_title, collapsible_table=collapsible_table)

    @staticmethod
    def compare_row_num(actual_table: list, expected_rows=None):
        """
        Compare expected row number with actual table
        :param expected_rows: number of expected rows for actual_table
        :param actual_table: actual table
        """
        info(f"compare_row_num(), {expected_rows=}")
        if expected_rows:
            assert len(actual_table) == expected_rows, \
                f"\n  {len(actual_table)=}, but\n{expected_rows=}\n{actual_table=}"

    def compare_actual_and_expected_tables(self, expected_table: list, actual_table=None, table_name: str = "",
                                           two_sections_table=False):
        """
        Compare actual and an expected tables
        :param expected_table: expected table
        :param actual_table: actual table
        :param table_name: the name of the actual table
        :param two_sections_table: True for 2 a section table, otherwise False
        """
        info(f"compare_actual_and_expected_tables(), {table_name=}, {two_sections_table=}")
        if not actual_table:
            if two_sections_table:
                actual_table = self.get_the_two_sections_table()
            else:
                info(f"Get all data from the table '{table_name}' and store it in 'actual_table'.")
                actual_table = self.move_to_table_and_get_data(table_name)

        info("Compare 'actual_table' and 'expected_table'.")
        error = ''
        actual_len = len(actual_table)
        expected_len = len(expected_table)

        if actual_len != expected_len:
            error += f"\n  {actual_len=}, but\n{expected_len=}"

        for row in range(min(actual_len, expected_len)):
            if actual_table[row] != expected_table[row]:
                error += f"\nrow '{row}' in actual_table == {actual_table[row]}, but" \
                         f"\n  row in expected_table == {expected_table[row]}"
        assert not error, error

    def compare_column_headers_and_row_num(self, expected_header: list, actual_table: list, expected_rows=None):
        """
        Compare expected column headers and row number with actual table
        :param expected_header: expected header in the format of [[header1,header2,header3]]
        :param expected_rows: number of expected rows for actual_table
        :param actual_table: actual table
        """
        self.compare_row_num(actual_table, expected_rows)
        self.compare_actual_and_expected_tables(expected_header[:1], actual_table[:1])

    @staticmethod
    def get_api_data_from_json_file(file_name) -> list:
        """
        TODO: Delete this method when we start to use real API responses
        Get the API data from a json file
        :param file_name: name of the json file
        :return: converted data
        """
        with open(file_name, "r") as api_data_file:
            return json.load(api_data_file)["data"]
