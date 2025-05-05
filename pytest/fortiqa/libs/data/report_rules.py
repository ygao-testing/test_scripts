from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
@dataclass
class ReportRuleData:
    guid: str
    name: str
    description: str
    created_or_updated_by: str
    enabled: bool
    alert_channels: List[str]
    type: str

    @staticmethod
    def from_api(api_result: Dict[str, Any]) -> 'ReportRuleData':
        """
        Create a ReportRuleData instance from an API result.

        Args:
            api_result (Dict[str, Any]): The dictionary containing API result data.

        Returns:
            ReportRuleData: An instance of the ReportRuleData class populated with data from the API result.
        """
        filters = api_result.get("filters", {})
        return ReportRuleData(
            guid=api_result.get("mcGuid", ""),
            name=filters.get("name", ""),
            description=filters.get("description", ""),
            created_or_updated_by=filters.get("createdOrUpdatedBy", ""),
            enabled=bool(filters.get("enabled", 0)),
            alert_channels=api_result.get("intgGuidList", []),
            type=api_result.get("type", "")
        )

    @staticmethod
    def from_tf(tf_result: Dict[str, Any]) -> 'ReportRuleData':
        """
        Create an ReportRuleData instance from a Terraform result dictionary.
        Args:
            tf_result (Dict[str, Any]): The dictionary containing Terraform result data.
        Returns:
            ReportRuleData: An instance of ReportRuleData populated with data from the Terraform result.
        """
        return ReportRuleData(
            guid=tf_result.get("guid", ""),
            name=tf_result.get("name", ""),
            description=tf_result.get("description") or "",
            created_or_updated_by=tf_result.get("created_or_updated_by", ""),
            enabled=tf_result.get("enabled", False),
            alert_channels=tf_result.get("email_alert_channels", []),
            type=tf_result.get("type", "")
        )

    def match(self, other: Any) -> bool:
        """
        Compares this ReportRuleData instance with another object to determine if they match.

        Args:
            other (Any): The object to compare with this ReportRuleData instance.

        Returns:
            bool: True if the other object is an ReportRuleData instance and all attributes match, False otherwise.

        The helper function `_report_notification_types_match` checks for partial matches.
        """
        if not isinstance(other, ReportRuleData):
            return False
        return (
            self.guid == other.guid and
            self.name == other.name and
            self.description == other.description and
            self.created_or_updated_by == other.created_or_updated_by and
            self.enabled == other.enabled and
            self.alert_channels == other.alert_channels and
            self.type == other.type
        )
