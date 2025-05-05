from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AlertRuleData:
    alert_categories: List[str]
    alert_channels: List[str]
    alert_sources: List[str]
    alert_subcategories: List[str]
    created_or_updated_by: str
    description: str
    enabled: bool
    guid: str
    id: str
    name: str
    resource_groups: Optional[List[str]]
    severities: List[str]
    type: str
    severity_mapping: dict = field(default_factory=lambda: {
        "Critical": "1",
        "High": "2",
        "Medium": "3",
        "Low": "4",
        "Info": "5"
    })

    def __post_init__(self):
        self.severities = [
            self.severity_mapping.get(severity, severity)
            for severity in self.severities
        ]

    @classmethod
    def from_tf(cls, data: dict):
        """Creates an instance of the class from a dictionary of data.

        Args:
            data (dict): A dictionary containing the data to initialize the instance.

        Returns:
            An instance of the class initialized with the provided data.
        """
        return cls(
            alert_categories=data.get("alert_categories", []),
            alert_channels=data.get("alert_channels", []),
            alert_sources=data.get("alert_sources", []),
            alert_subcategories=data.get("alert_subcategories", []),
            created_or_updated_by=data.get("created_or_updated_by", ""),
            description=data.get("description", ""),
            enabled=data.get("enabled", False),
            guid=data.get("guid", ""),
            id=data.get("id", ""),
            name=data.get("name", ""),
            resource_groups=data.get("resource_groups") or [],
            severities=data.get("severities", []),
            type=data.get("type", "")
        )

    @classmethod
    def from_api(cls, data: dict):
        """
        Create an instance of the class from API data.

        Args:
            data (dict): A dictionary containing the API data.

        Returns:
            An instance of the class with attributes populated from the API data.
        """
        filters = data.get("filters", {})
        return cls(
            alert_categories=filters.get("category", []),
            alert_channels=data.get("intgGuidList", []),
            alert_sources=filters.get("source", []),
            alert_subcategories=filters.get("subCategory", []),
            created_or_updated_by=filters.get("createdOrUpdatedBy", ""),
            description=filters.get("description", ""),
            enabled=filters.get("enabled", 0) == 1,
            guid=data.get("mcGuid", ""),
            id=data.get("mcGuid", ""),
            name=filters.get("name", ""),
            resource_groups=filters.get("resourceGroups", []),
            severities=[str(severity) for severity in filters.get("severity", [])],
            type=data.get("type", "")
        )

    def match(self, other):
        """Compares this instance with another object to determine if they match."""
        return (
            self.alert_categories == other.alert_categories and
            self.alert_channels == other.alert_channels and
            self.alert_sources == other.alert_sources and
            self.alert_subcategories == other.alert_subcategories and
            self.created_or_updated_by == other.created_or_updated_by and
            self.description == other.description and
            self.enabled == other.enabled and
            self.guid == other.guid and
            self.id == other.id and
            self.name == other.name and
            self.resource_groups == other.resource_groups and
            self.severities == other.severities and
            self.type == other.type
        )
