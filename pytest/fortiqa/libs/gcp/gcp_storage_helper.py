import logging

from fortiqa.libs.gcp.gcp_helper import GCPHelper

log = logging.getLogger(__name__)


class Storage(GCPHelper):
    """Google Cloud Storage (GCS) Helper functions using google-cloud-storage client"""

    def __init__(self, credentials_path: str = ""):
        super().__init__(gcp_service="storage", credentials_path=credentials_path)

    def list_buckets(self):
        """List all GCS buckets names in the project."""
        buckets = list(self.client.list_buckets())
        log.info(f"Found {len(buckets)} buckets.")
        return [bucket.name for bucket in buckets]

    def create_bucket(self, bucket_name: str):
        """
        Create a new GCS bucket.

        :param bucket_name: Name of the new Bucket
        """
        self.client.create_bucket(bucket_name)
        log.info(f"Bucket '{bucket_name}' created successfully.")

    def upload_file(self, bucket_name: str, source_file: str, destination_blob: str):
        """
        Upload a file to a GCS bucket.

        :param bucket_name: Name of the GCS bucket
        :param source_file: Local file path
        :param destination_blob: Destination path in GCS
        """
        bucket = self.client.bucket(bucket_name)
        blob = bucket.blob(destination_blob)
        blob.upload_from_filename(source_file)
        log.info(f"File {source_file} uploaded to {destination_blob} in bucket {bucket_name}.")

    def download_file(self, bucket_name: str, source_blob: str, destination_file: str):
        """
        Download a file from a GCS bucket.

        :param bucket_name: Name of the GCS bucket
        :param source_blob: Source path in GCS
        :param destination_file: Local file path to save the downloaded file
        """
        bucket = self.client.bucket(bucket_name)
        blob = bucket.blob(source_blob)
        blob.download_to_filename(destination_file)
        log.info(f"File {source_blob} downloaded from bucket {bucket_name} to {destination_file}.")

    def delete_bucket(self, bucket_name: str):
        """Delete a GCS bucket."""
        bucket = self.client.bucket(bucket_name)
        bucket.delete(force=True)  # Deletes non-empty buckets
        log.info(f"Bucket '{bucket_name}' deleted successfully.")
