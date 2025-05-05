from dataclasses import dataclass
from typing import List, Optional


@dataclass
class VulnerabilitySearchPayload:
    timeFilter: Optional[dict]
    filters: Optional[List[dict]]
    returns: Optional[List[str]]


@dataclass
class QueryPayload:
    queryText: str
    queryId: str


def filter_none_values(payload) -> dict:
    """
    Payload for post and put requests may contain optional fields,
    based on the test being performed different test can pass different payloads.
    This function removes the fields from the payload whose value is None, and returns a dict

    :param payload: Payload passed to post/put request.
    """
    attributes = vars(payload)
    result = {}
    for key, value in attributes.items():
        if attributes[key] is not None:
            result[key] = value
    return result
