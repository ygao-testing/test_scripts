"""Resource Explorer page"""
import logging

from fortiqa.tests.ui.utils.base_helper import BaseUiHelper

info = logging.getLogger(__name__).info


class ResourceExplorerPage(BaseUiHelper):
    """Resource Explorer page"""

    def verify_resource_explorer_page(self):
        """Verify Resource Explorer page"""
        info("1. Open 'Resource Explorer' page.")
        self.open_page("Resource Explorer")
        # table = self.get_the_two_sections_table()
