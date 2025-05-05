import logging

from fortiqa.libs.gcp.gcp_helper import GCPHelper
from google.cloud import compute_v1

log = logging.getLogger(__name__)


class ComputeHelper(GCPHelper):
    """Helper class for managing Compute Engine instances in GCP."""

    def __init__(self, project_id: str, zone: str, credentials_path: str = ""):
        """
        Initialize GCP Compute Engine helper.

        :param project_id: GCP Project ID
        :param zone: Default zone where instances are managed
        """
        super().__init__(gcp_service="compute", credentials_path=credentials_path)
        self.project_id = project_id
        self.zone = zone

    def list_instances(self):
        """List all VM instances in the specified zone."""
        request = compute_v1.ListInstancesRequest(project=self.project_id, zone=self.zone)
        instances = self.client.list(request=request)
        instance_list = [instance.name for instance in instances]
        log.info(f"Instances in {self.zone}: {instance_list}")
        return instance_list

    def get_instance(self, instance_name: str):
        """Get details of a specific instance.

        :param instance_name: Name of the new instance
        """
        request = compute_v1.GetInstanceRequest(
            project=self.project_id, zone=self.zone, instance=instance_name
        )
        instance = self.client.get(request=request)
        log.info(f"Instance {instance_name} details: {instance}")
        return instance

    def start_instance(self, instance_name: str):
        """Start a Compute Engine instance.

        :param instance_name: Name of the new instance
        """
        request = compute_v1.StartInstanceRequest(
            project=self.project_id, zone=self.zone, instance=instance_name
        )
        operation = self.client.start(request=request)
        log.info(f"Starting instance {instance_name}...")
        return operation

    def stop_instance(self, instance_name: str):
        """
        Stop a Compute Engine instance.

        :param instance_name: Name of the new instance
        """
        request = compute_v1.StopInstanceRequest(
            project=self.project_id, zone=self.zone, instance=instance_name, discard_local_ssd=True
        )
        operation = self.client.stop(request=request)
        log.info(f"Stopping instance {instance_name}...")
        return operation

    def delete_instance(self, instance_name: str):
        """
        Delete a Compute Engine instance.

        :param instance_name: Name of the new instance
        """
        request = compute_v1.DeleteInstanceRequest(
            project=self.project_id, zone=self.zone, instance=instance_name
        )
        operation = self.client.delete(request=request)
        log.info(f"Deleting instance {instance_name}...")
        return operation
