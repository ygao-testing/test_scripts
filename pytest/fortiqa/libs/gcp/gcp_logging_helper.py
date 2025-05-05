import logging

from fortiqa.libs.gcp.gcp_helper import GCPHelper

log = logging.getLogger(__name__)


class LoggingHelper(GCPHelper):
    """Google Cloud Publisher Helper functions using google-cloud-logging client"""

    def __init__(self, project_id: str, credentials_path: str = ""):
        super().__init__(gcp_service="logging", credentials_path=credentials_path)
        self.project_path = f"projects/{project_id}"

    def list_sinks(self) -> list:
        """List all sink object name under the project."""
        sinks = self.client.list_sinks(parent=self.project_path)
        log.info(f"Found {sinks=}.")
        return [sink.name for sink in sinks]
