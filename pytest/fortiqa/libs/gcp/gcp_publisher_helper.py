import logging
import time

from fortiqa.libs.gcp.gcp_helper import GCPHelper

log = logging.getLogger(__name__)


class PubliserHelper(GCPHelper):
    """Google Cloud Publisher Helper functions using google-cloud-pubsub client"""

    def __init__(self, project_id: str, credentials_path: str = ""):
        super().__init__(gcp_service="pubsub", credentials_path=credentials_path)
        self.project_path = f"projects/{project_id}"

    def list_topics(self) -> list:
        """List all topic names under the project."""
        topics = self.client.list_topics(request={"project": self.project_path})
        log.info(f"Found {topics=}.")
        return [topic.name for topic in topics]

    def wait_until_pub_appear(self, topic_id: str, timeout: int = 600):
        """
        Function to check publisher is created in current GCP Project
        :param topic_id: The topic to be found
        :raises: `TimeoutError` if there is no expected publisher topic created in the GCP Project
        """
        log.info(f"Finding topic {topic_id}")
        found_topic = False
        start_time = time.monotonic()
        time_passed = 0
        while time_passed < timeout and not found_topic:
            time_passed = int(time.monotonic() - start_time)
            all_topics = self.list_topics()
            if topic_id in all_topics:
                found_topic = True
            else:
                time.sleep(60)
        if not found_topic:
            log.debug(f"Topics inside GCP: {all_topics}, Expected topic: {topic_id} after {time_passed} sec")
            raise TimeoutError(f"There is no topic {topic_id} inside GCP project after {time_passed} sec")
        return True
