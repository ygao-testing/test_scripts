from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class IAMUser:
    """Represents an IAM User."""
    account_id: str
    path: str
    user_name: str
    user_id: str
    arn: str
    create_date: str  # ISO 8601 formatted string
    password_last_used: Optional[str] = None  # ISO 8601 formatted string
    tags: dict[str, str] = field(default_factory=dict)
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None


@dataclass
class IAMGroup:
    """Represents an IAM Group."""
    account_id: str
    path: str
    group_name: str
    group_id: str
    arn: str
    create_date: str  # ISO 8601 formatted string


@dataclass
class IAMPolicy:
    """Represents an IAM Policy."""
    account_id: str
    policy_name: str
    policy_id: str
    arn: str
    path: str
    default_version_id: str
    attachment_count: int
    permissions_boundary_usage_count: int
    is_attachable: bool
    create_date: str  # ISO 8601 formatted string
    update_date: str  # ISO 8601 formatted string
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class AssumeRolePolicyStatement:
    """Represents a statement in the AssumeRolePolicyDocument."""
    sid: Optional[str] = None
    effect: str = ""
    principal: dict[str, Any] = field(default_factory=dict)
    action: list[str] = field(default_factory=list)
    condition: Optional[dict[str, Any]] = None


@dataclass
class AssumeRolePolicyDocument:
    """Represents the AssumeRolePolicyDocument of an IAM Role."""
    version: str = ""
    id: Optional[str] = None
    statement: list[AssumeRolePolicyStatement] = field(default_factory=list)


@dataclass
class IAMRole:
    """Represents an IAM Role."""
    account_id: str
    path: str
    role_name: str
    role_id: str
    arn: str
    create_date: str  # ISO 8601 formatted string
    assume_role_policy_document: AssumeRolePolicyDocument
    description: Optional[str] = None
    max_session_duration: int = 3600
    tags: dict[str, str] = field(default_factory=dict)
