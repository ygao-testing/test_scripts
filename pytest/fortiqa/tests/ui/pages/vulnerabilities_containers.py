"""Vulnerabilities Containers page"""
import logging

from fortiqa.tests.ui.utils.base_helper import BaseUiHelper

info = logging.getLogger(__name__).info


class VulnerabilitiesContainersPage(BaseUiHelper):
    """Vulnerabilities Containers page"""

    def verify_vulnerabilities_containers_page(self):
        """Verify Vulnerabilities Containers"""
        info("1. Open 'Vulnerabilities Containers' page.")
        self.open_page("Vulnerabilities Containers")
