import logging
import json
from json.decoder import JSONDecodeError
from typing import Any
logger = logging.getLogger(__name__)


def build_dynamic_payload(time_filter: dict, filters: list[Any] | None = None, csp: str | None = None, returns: list[Any] | None = None) -> str:
    """
    Dynamically builds the payload for an API call.

    Parameters:
    - time_filter (dict): A dictionary with 'startTime' and 'endTime' values representing the
      time filter.
    - filters (list, optional): A list of filter dictionaries to apply to the search
      (default is an empty list).
    - csp (str, optional): The cloud service provider (e.g., 'AWS', 'GCP', 'Azure'). It should
      be provided when required by certain APIs like the inventory API.
    - returns (list, optional): A list of fields to return in the response (default is a
      predefined set of fields).


    Returns:
    A JSON string representing the payload.

    Example payload for search inventory API:
    {
       "timeFilter": {
           "startTime": "2024-10-04T00:00:00Z",
           "endTime": "2024-10-05T00:00:00Z"
       },
       "filters": [
           {
              "expression": "eq",
              "field": "resourceRegion",
              "value": "us-east-2"
           },
           {
              "expression": "eq",
              "field": "resourceType",
              "value": "ec2:instance"
           },
           {
              "expression": "rlike",
              "field": "resourceConfig.SecurityGroups",
              "value": ".*sg-.*"
           }
       ],
       "returns": [
           "cloudDetails", "csp", "resourceConfig", "resourceId", "resourceType",
           "resourceRegion", "startTime", "endTime"
       ],
       "csp": "AWS"
    }

    """
    filters = filters or []
    returns = returns or [
        "cloudDetails", "csp", "resourceConfig", "resourceId", "resourceType",
        "resourceRegion", "resourceTags", "status", "urn", "startTime", "endTime"
        ]

    payload = {
            "timeFilter": {
                "startTime": time_filter['startTime'],
                "endTime": time_filter['endTime']
            },
            "filters": filters,
            "returns": returns,

        }
    if csp:
        payload["csp"] = csp

    return json.dumps(payload, indent=4)


def check_and_return_json_from_response(api_response):
    """
    Validates the API response and returns the content in JSON format.

    This method attempts to retrieve the JSON content from the given API response. If the
    response is not valid JSON, it logs the exception and raises a ValueError.

    Parameters:
    - api_response: The response object from an API call.

    Returns:
    - The JSON content if the response body is valid JSON.

    Raises:
    - ValueError: If the response body is not valid JSON.
    """
    try:
        return api_response.json()
    except JSONDecodeError:
        logger.exception("Failed to decode JSON from the API response")
        raise ValueError("Response body is not valid JSON")
