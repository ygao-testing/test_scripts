from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class AlertChannelData:
    name: str
    type: str
    enabled: bool
    recipients: List[str]
    intg_guid: str
    created_or_updated_by: str

    @staticmethod
    def from_tf(resource: Dict[str, Any]) -> 'AlertChannelData':
        """
        Parse a Terraform resource dictionary into an AlertChannelData instance.

        Args:
            resource (Dict[str, Any]): The Terraform resource dictionary.

        Returns:
            AlertChannelData: The parsed AlertChannelData instance.
        """
        return AlertChannelData(
            name=resource.get("name", ""),
            type=resource.get("type_name", ""),
            enabled=resource.get("enabled", False),
            recipients=resource.get("recipients", []),
            intg_guid=resource.get("intg_guid", ""),
            created_or_updated_by=resource.get("created_or_updated_by", ""),
        )

    @staticmethod
    def from_api(resource: Dict[str, Any]) -> 'AlertChannelData':
        """
        Parse an API resource dictionary into an AlertChannelData instance.

        Args:
            resource (Dict[str, Any]): The API resource dictionary.

        Returns:
            AlertChannelData: The parsed AlertChannelData instance.
        """
        return AlertChannelData(
            name=resource.get("name", ""),
            type=resource.get("type", ""),
            enabled=bool(resource.get("enabled", False)),
            recipients=[resource.get("data", {}).get("channelProps", {}).get("recipients", "")],
            intg_guid=resource.get("intgGuid", ""),
            created_or_updated_by=resource.get("createdOrUpdatedBy", ""),
        )

    def match(self, other: 'AlertChannelData') -> bool:
        """
        Match this AlertChannelData instance with another instance.
        Args:
            other (AlertChannelData): The other AlertChannelData instance to compare with.
        Returns:
            bool: True if both instances are equal within the given tolerance, False otherwise.
        """
        return (
            self.name == other.name and
            self.type == other.type and
            self.enabled == other.enabled and
            self.recipients == other.recipients and
            self.intg_guid == other.intg_guid and
            self.created_or_updated_by == other.created_or_updated_by
        )
