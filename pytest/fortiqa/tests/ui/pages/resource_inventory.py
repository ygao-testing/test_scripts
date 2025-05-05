"""Resource Inventory page"""
import logging

from fortiqa.tests.ui.utils.base_helper import BaseUiHelper

info = logging.getLogger(__name__).info


class ResourceInventoryPage(BaseUiHelper):
    """Resource Inventory page"""

    def verify_resource_inventory_page(self):
        """Verify Resource Inventory page"""
        info("1. Open 'Resource Inventory' page.")
        self.open_page("Resource Inventory")
        resource_inventory_table = self.get_the_two_sections_table()
        info(f"{resource_inventory_table=}")
