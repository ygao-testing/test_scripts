import logging
from typing import Any
from fortiqa.libs.aws.data_class.ec2_data_classes import Snapshot
from fortiqa.libs.aws.awshelper import AWSHelper
from fortiqa.libs.helper.date_helper import datetime_to_iso8601
from fortiqa.tests import settings


logger = logging.getLogger(__name__)


class Ec2SnapshotHelper(AWSHelper):

    def __init__(self, region='us-east-2', aws_credentials: dict = {}):
        super().__init__(boto3_client='ec2', region=region, aws_credentials=aws_credentials)

    def get_all_snapshots_raw(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """Retrieve raw snapshot data for the specified AWS region, optionally filtered by tags.

        This method calls the AWS EC2 'describe_snapshots' API to gather information about all
        snapshots owned by the current account within the specified region. If tags are provided,
        only snapshots with the specified tags are included.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        snapshots based on tags. If None, retrieves all snapshots.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, each containing details for an
            individual snapshot within the specified region.
        """
        logger.info(
            f"Retrieving Snapshots from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}"
        )
        filters = [{"Name": f"tag:{key}", "Values": [value]} for key, value in tags.items()] if tags else None
        response = self.client.describe_snapshots(OwnerIds=['self'], Filters=filters) if filters else self.client.describe_snapshots(OwnerIds=['self'])
        snapshots = response.get("Snapshots", [])
        logger.debug(
            f"Snapshot data retrieved from AWS account {self.account_id} in region: {self.region}"
            f"{f', with tags {tags}' if tags else ''}: {snapshots}"
        )
        return snapshots

    def get_all_snapshot_objects(self, tags: dict[str, str] | None = None) -> list[Snapshot]:
        """Convert raw snapshot data to a list of Snapshot objects for the specified region,
        optionally filtered by tags.

        This method takes the raw snapshot data obtained from the 'get_all_snapshots_raw' method,
        processes each snapshot's attributes, and converts them into a list of 'Snapshot' data
        class objects.

        Args:
            tags (dict[str, str] | None): A dictionary containing key-value pairs for filtering
                                        snapshots based on tags. If None, retrieves all snapshots.

        Returns:
            list[Snapshot]: A list of 'Snapshot' objects representing each snapshot in the specified
            region.
        """
        snapshots = self.get_all_snapshots_raw(tags)
        snapshot_objects = []

        for snapshot in snapshots:
            logger.debug(f"Snapshot data received from AWS for conversion: {snapshot}")
            tags = {tag["Key"]: tag["Value"] for tag in snapshot.get("Tags", [])}
            start_time = datetime_to_iso8601(snapshot.get("StartTime"))
            # Create Snapshot object
            snapshot_obj = Snapshot(
                snapshot_id=snapshot.get("SnapshotId", ""),
                account_id=settings.app.aws_account.aws_account_id,
                volume_id=snapshot.get("VolumeId", ""),
                state=snapshot.get("State", ""),
                start_time=start_time,
                progress=snapshot.get("Progress", ""),
                owner_id=snapshot.get("OwnerId", ""),
                description=snapshot.get("Description", ""),
                volume_size=snapshot.get("VolumeSize", 0),
                encrypted=snapshot.get("Encrypted", False),
                storage_tier=snapshot.get("StorageTier", ""),
                tags=tags
            )

            snapshot_objects.append(snapshot_obj)

        return snapshot_objects
