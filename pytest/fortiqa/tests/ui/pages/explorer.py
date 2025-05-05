"""Explorer page"""
import logging
from time import sleep

from fortiqa.tests.ui.data.explorer_queries import saved_queries
from fortiqa.tests.ui.utils.base_helper import BaseUiHelper
from fortiqa.tests.ui.utils.webelements_helper import dropdown_right_text_area
from fortiqa.tests.ui.tests.explorer.test_explorer import saved_query_names

info = logging.getLogger(__name__).info

# Landing
landing_heading = '(//div[contains(@class,"LandingPage")]//div[@role="heading"])[2]'
# Graph
find_a_query_input = '//input[@placeholder="Find a query"]'
selected_query_name = '//div[text()="Select a saved query"]/ancestor::button/span//span[@class="SavedQueriesDropdown_dropdownTriggerTag__-r4e9"]'
query_parameters_sections_text = '//div[@class="trellis-query-builder-view"]//div[contains(@style,"display: flex; flex-direction: row; margin-bottom")]'
query_builder_dropdown = '//div[contains(@class,"query-builder-dropdown-trigger")]'
query_result = '//div[contains(@class,"SecurityGraphTableStyle_container")]'


class ExplorerPage(BaseUiHelper):
    """Explorer page"""

    def build_your_own_query_button(self):
        """Test "Build your own query" button on Landing page"""
        self.open_page("Explorer")
        self.click_tab("Landing")
        self.click_btn("Build your own query")
        self.click_tab("Graph", verify_only=True)

    def verify_query(self, tab: str = "Landing", saved_query_name: str = "",
                     custom_query_data: dict | None = None):
        """
        Generate saved or customized query on Explorer page and verify the results.
        :param tab: Select tab from the top of Explorer page. e.g. "Landing", "Graph"
        :param saved_query_name: The name of the saved query
        :param custom_query_data: Custom Query data
        TODO: For now it works only for saved query and it doesn't check the Query results. Add it to the method.
        """
        self.open_page("Explorer")

        if saved_query_name:
            if tab == "Landing":
                self.click_tab("Landing")
                expected_text = (
                        "Welcome to\nExplorer\nBuild your own query or start with a saved one\nBuild your own query\n"
                        + "\n".join(saved_query_names))
                error = self.verify_text(xpath=landing_heading + "/..", expected_text=expected_text)
                assert not error, error
                self.click_by_text(saved_query_name)
            elif tab == "Graph":
                self.click_tab("Graph")
                self.search_saved_query(saved_query_name)

        elif custom_query_data:
            self.click_tab("Graph")

            info("Build a custom query")
            info(f"1. Select the return type. {custom_query_data['clauses']}")
            # 1. Open the dropdown menu.
            # 2. Select the Host type.
            # 3. Click the "Update clause" button.
            info("2. Add Clauses.")
            for clause in custom_query_data["clauses"]:
                info(f"{clause=}")
                # 1. Click the "Add clause" button (open the dropdown menu).
                # 2. Search for the Clause name.
                # 3. Select the Clause name. Select the subname if it is necessary.
                # 4. Fill the data form (checkboxes, dropdown lists, etc.)
                # 5. Click the submit button ("Add clause" button).

            self.click_btn("Search")

        self.wait_until_loading_sign_disappears()
        # TODO: The expected_table we should get from API
        # self.compare_actual_and_expected_tables(expected_table=[], table_name="Query results", two_sections_table=True)
        query_results = self.get_the_two_sections_table()
        info(f"{query_results=}")

    def search_saved_query(self, saved_query_name: str):
        """
        Search saved query on Graph page and verify basic info of the selected query
        :param saved_query_name: The name of the saved query
        """
        info("Select a Saved query")
        if self.is_element_present(query_result):
            self.click(query_builder_dropdown)
            sleep(1)
            self.click_btn("Clear query")
        if not self.is_element_present(find_a_query_input):
            self.click_by_text("Select a saved query")
        self.search_by_text(placeholder="Find a query", value=saved_query_name)

        info("Verify the result on the right side of the dropdown list")
        error = self.verify_text(xpath=dropdown_right_text_area,
                                 expected_text=saved_queries[saved_query_name]["query_text"])
        assert not error, error
        self.click_btn("Apply query")

        info("Verify query name in the dropdown list")
        error = self.verify_text(xpath=selected_query_name, expected_text=saved_query_name)

        info("Verify query data")
        actual_query_data = self.get_text_from_several_elements(query_parameters_sections_text)
        error += self.verify_text(expected_text=saved_queries[saved_query_name]["query_data"],
                                  actual_text=actual_query_data)
        assert not error, error
        self.click_btn("Search")
