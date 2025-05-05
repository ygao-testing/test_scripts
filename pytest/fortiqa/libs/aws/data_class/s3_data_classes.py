
from dataclasses import dataclass


@dataclass
class S3Bucket:
    name: str
    creation_date: str  # Store as formatted string
    account_id: str
