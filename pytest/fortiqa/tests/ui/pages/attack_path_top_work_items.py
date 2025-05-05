"""Attack Path Top Work Items page"""
import logging

from fortiqa.tests.ui.utils.base_helper import BaseUiHelper

info = logging.getLogger(__name__).info


class TopWorkItemsPage(BaseUiHelper):
    """Attack Path Top Work Items page"""

    def verify_top_work_items_page(self):
        """Verify the Attack Path Top Work Items page"""
        info("1. Open 'Top work Items' page.")
        self.open_page("Top work items")
