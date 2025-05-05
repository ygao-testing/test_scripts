import logging
from typing import Any
from fortiqa.libs.aws.data_class.ec2_data_classes import Volume, VolumeAttachment
from fortiqa.libs.aws.awshelper import AWSHelper
from fortiqa.tests import settings

logger = logging.getLogger(__name__)


class Ec2VolumeHelper(AWSHelper):

    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client='ec2', region=region, aws_credentials=aws_credentials)

    def get_all_volumes_raw(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Retrieve raw volume data for the specified AWS region, optionally filtered by tags.

        This method calls the AWS EC2 'describe_volumes' API to gather information about all
        volumes within the specified region. If tags are provided, only volumes with the
        specified tags are included.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        volumes based on tags. If None, retrieves all volumes.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing details for an
                                individual volume within the specified region.
        """
        logger.info(
            f"Retrieving Volumes from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}"
        )
        filters = [{"Name": f"tag:{key}", "Values": [value]} for key, value in tags.items()] if tags else None
        response = self.client.describe_volumes(Filters=filters) if filters else self.client.describe_volumes()
        volumes = response.get("Volumes", [])
        logger.debug(
            f"Volume data retrieved from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}: {volumes}"
        )
        return volumes

    def get_all_volume_objects(self, tags: dict[str, str] | None = None) -> list[Volume]:
        """Convert raw volume data to a list of Volume objects for the specified region,
        optionally filtered by tags.

        This method takes the raw volume data obtained from the 'get_all_volumes_raw' method,
        processes each volume's attributes, and converts them into a list of Volume' data
        class objects.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        volumes based on tags. If None, retrieves all volumes.

        Returns:
            list[Volume]: A list of `Volume` objects representing each volume in the specified region.
        """
        volumes = self.get_all_volumes_raw(tags)
        volume_objects = []

        for volume in volumes:
            # Convert Attachments
            attachments = [
                VolumeAttachment(
                    delete_on_termination=attachment.get("DeleteOnTermination", False),
                    volume_id=attachment.get("VolumeId", ""),
                    instance_id=attachment.get("InstanceId", ""),
                    device=attachment.get("Device", ""),
                    state=attachment.get("State", ""),
                    attach_time=attachment.get("AttachTime", "")
                )
                for attachment in volume.get("Attachments", [])
            ]

            # Convert Tags to dictionary
            tags = {tag["Key"]: tag["Value"] for tag in volume.get("Tags", [])}

            # Create Volume object
            volume_obj = Volume(
                volume_id=volume.get("VolumeId", ""),
                account_id=settings.app.aws_account.aws_account_id,
                iops=volume.get("Iops", 0),
                size=volume.get("Size", 0),
                snapshot_id=volume.get("SnapshotId") or None,  # Convert empty string to None
                availability_zone=volume.get("AvailabilityZone", ""),
                state=volume.get("State", ""),
                create_time=volume.get("CreateTime", ""),
                volume_type=volume.get("VolumeType", ""),
                multi_attach_enabled=volume.get("MultiAttachEnabled", False),
                encrypted=volume.get("Encrypted", False),
                throughput=volume.get("Throughput"),  # Optional field
                attachments=attachments,
                tags=tags
            )

            volume_objects.append(volume_obj)

        return volume_objects
