"""Base UI Helper class"""

import logging

from fortiqa.tests.ui.data.tech_doc import tech_doc_page_data
from fortiqa.tests.ui.utils.table_helper import TableHelper

info = logging.getLogger(__name__).info

title_text = "//div[contains(@class, 'rhs')]/h1"


class BaseUiHelper(TableHelper):
    """Store all methods that are not placed in other Helpers"""

    def open_tech_doc_and_verify(self, link_name: str):
        """
        Open Technical Documentation pagn and verify
        1. Open the link.
        2. Switch to the new window.
        3. Verify URL.
        4. Verify page Title.
        5. Close the new window and switch to the main window.
        :param link_name: Link name
        """
        info(f"open_tech_doc_and_verify(), {link_name=}")
        info("1. Open the link.")
        self.click_by_text(link_name)

        info("2. Switch to the new window.")
        main_window_handle = self.switch_to_new_window()

        info("3. Verify URL.")
        error = self.verify_url(expected_url=tech_doc_page_data[link_name]["url"], return_error_text=True)

        info("4. Verify page Title.")
        expected_text = tech_doc_page_data[link_name]["title_text"]
        error += self.verify_text(xpath=title_text, expected_text=expected_text)  # type: ignore
        assert not error, error

        info("5. Close the new window and switch to the main window.")
        self.close_page()
        self.switch_to_main_window(main_window_handle)
