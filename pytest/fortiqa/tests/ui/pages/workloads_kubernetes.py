"""Workloads Kubernetes page"""
import logging

from fortiqa.tests.ui.utils.base_helper import BaseUiHelper

info = logging.getLogger(__name__).info


class WorkloadsKubernetesPage(BaseUiHelper):
    """Workloads Kubernetes page"""

    def verify_workloads_kubernetes_page(self):
        """Verify the Workloads Kubernetes page"""
        info("1. Open 'Workloads Kubernetes' page.")
        self.open_page("Workloads Kubernetes")
