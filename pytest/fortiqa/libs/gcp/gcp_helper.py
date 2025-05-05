import logging
import os
from google.cloud import storage, pubsub_v1, logging_v2, compute_v1

log = logging.getLogger(__name__)


class GCPHelper:
    """GCP general helper"""
    def __init__(self, gcp_service: str, credentials_path: str = ""):
        """
        Initialize a GCP client.

        :param gcp_service: Name of the GCP service (e.g., 'storage', 'bigquery')
        :param credentials_path: Path to the GCP service account JSON file.
                                 If None, use the default credentials.
        """
        if credentials_path:
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = credentials_path

        self.client = self._initialize_client(gcp_service)
        log.info(f"GCP {gcp_service} client initialized successfully.")

    def _initialize_client(self, gcp_service: str):
        """
        Initialize and return the correct GCP client.

        :param gcp_service: GCP service name
        :return: GCP client instance
        """
        service_map = {
            "storage": storage.Client,
            "pubsub": pubsub_v1.PublisherClient,
            "logging": logging_v2.Client,
            "compute": compute_v1.InstancesClient,
            # Add other services as needed (e.g., "bigquery": bigquery.Client)
        }
        if gcp_service not in service_map:
            raise ValueError(f"Unsupported GCP service: {gcp_service}")
        return service_map[gcp_service]()
