from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class PolicyData:
    id: str
    title: str
    description: str
    enabled: bool
    severity: str
    evaluation: str
    limit: int
    owner: str
    updated_by: str
    updated_time: str
    query_id: str
    remediation: str
    tags: List[str] = field(default_factory=list)
    alerting: Optional[List[dict]] = field(default_factory=list)

    @staticmethod
    def from_tf(tf_result: dict) -> 'PolicyData':
        """
        Create a PolicyData instance from a Terraform result dictionary.
        Args:
            tf_result (dict): A dictionary containing the Terraform result data.
        Returns:
            PolicyData: An instance of the PolicyData class populated with the data from the Terraform result.
        """
        return PolicyData(
            id=tf_result.get("id", ""),
            title=tf_result.get("title", ""),
            description=tf_result.get("description", ""),
            enabled=tf_result.get("enabled", False),
            severity=tf_result.get("severity", ""),
            evaluation=tf_result.get("evaluation", ""),
            limit=tf_result.get("limit", 0),
            owner=tf_result.get("owner", ""),
            updated_by=tf_result.get("updated_by", ""),
            updated_time=tf_result.get("updated_time", ""),
            query_id=tf_result.get("query_id", ""),
            remediation=tf_result.get("remediation", ""),
            tags=tf_result.get("tags", []),
            alerting=tf_result.get("alerting", [])
        )

    @staticmethod
    def from_api(api_result: dict) -> 'PolicyData':
        """
        Create a PolicyData instance from an API result dictionary.
        Args:
            api_result (dict): A dictionary containing the API result data.
        Returns:
            PolicyData: An instance of the PolicyData class populated with the data from the API result.
        """
        return PolicyData(
            id=api_result.get("policyId", ""),
            title=api_result.get("title", ""),
            description=api_result.get("description", ""),
            enabled=api_result.get("enabled", False),
            severity=api_result.get("severity", ""),
            evaluation=api_result.get("evalFrequency", ""),
            limit=api_result.get("limit", 0),
            owner=api_result.get("owner", ""),
            updated_by=api_result.get("lastUpdateUser", ""),
            updated_time=api_result.get("lastUpdateTime", ""),
            query_id=api_result.get("queryId", ""),
            remediation=api_result.get("remediation", ""),
            tags=api_result.get("tags", []),
            alerting=[{
                "enabled": api_result.get("alertEnabled", False),
                "profile": api_result.get("alertProfile", "")
            }]
        )

    def matches(self, other: 'PolicyData') -> bool:
        """
        Compare this PolicyData instance with another PolicyData instance to check if they match.
        Args:
            other (PolicyData): Another instance of the PolicyData class to compare with.
        Returns:
            bool: True if the two PolicyData instances match, False otherwise.
        """
        if not isinstance(other, PolicyData):
            return False

        def list_matches(list1, list2):
            if any(isinstance(i, dict) for i in list1 + list2):
                return all(i in list2 for i in list1) and all(i in list1 for i in list2)
            else:
                # there might be some default values added from the API side,
                # so check for partial match.
                return set(list1) == set(list2) or set(list1).issubset(set(list2)) or set(list2).issubset(set(list1))

        return (
            self.id == other.id and
            self.title == other.title and
            self.description == other.description and
            self.enabled == other.enabled and
            self.severity == other.severity and
            self.evaluation == other.evaluation and
            self.limit == other.limit and
            self.owner == other.owner and
            self.updated_by == other.updated_by and
            self.updated_time == other.updated_time and
            self.query_id == other.query_id and
            self.remediation == other.remediation and
            list_matches(self.tags, other.tags) and
            list_matches(self.alerting, other.alerting)
        )
