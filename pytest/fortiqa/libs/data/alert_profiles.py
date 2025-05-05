from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class Alert:
    name: str
    event_name: str
    description: str
    subject: str

    @staticmethod
    def from_api(api_alert: Dict[str, Any]) -> 'Alert':
        """Create an Alert instance from an API response dictionary."""
        return Alert(
            name=api_alert.get("name", ""),
            event_name=api_alert.get("eventName", ""),
            description=api_alert.get("description", ""),
            subject=api_alert.get("subject", "")
        )

    @staticmethod
    def from_tf(tf_alert: Dict[str, Any]) -> 'Alert':
        """Create an Alert instance from a tf object."""
        return Alert(
            name=tf_alert.get("name", ""),
            event_name=tf_alert.get("event_name", ""),
            description=tf_alert.get("description", ""),
            subject=tf_alert.get("subject", "")
        )


@dataclass
class AlertProfileData:
    id: str
    extends: str
    fields: List[str]
    alerts: List[Alert]

    @staticmethod
    def from_api(api_result: Dict[str, Any]) -> 'AlertProfileData':
        """Create an AlertProfileData instance from an API result."""
        # Convert API fields format to simple string list
        fields = [field["name"] for field in api_result.get("fields", [])]

        return AlertProfileData(
            id=api_result.get("alertProfileId", ""),
            extends=api_result.get("extends", ""),
            fields=sorted(fields),  # Sort for consistent comparison
            alerts=[Alert.from_api(alert) for alert in api_result.get("alerts", [])]
        )

    @staticmethod
    def from_tf(tf_result: Dict[str, Any]) -> 'AlertProfileData':
        """Create an AlertProfileData instance from a Terraform result."""
        return AlertProfileData(
            id=tf_result.get("id", ""),
            extends=tf_result.get("extends", ""),
            fields=sorted(tf_result.get("fields", [])),  # Sort for consistent comparison
            alerts=[Alert.from_tf(alert) for alert in tf_result.get("alert", [])]
        )

    def match(self, other: Any) -> bool:
        """Compare this AlertProfileData instance with another object."""
        if not isinstance(other, AlertProfileData):
            return False

        # Check for partial matches, as there might be default alerts in the API data
        alerts_match = all(alert in other.alerts for alert in self.alerts) or all(
            alert in self.alerts for alert in other.alerts
        )

        return (
            self.id == other.id and
            self.extends == other.extends and
            self.fields == other.fields and
            alerts_match
        )
