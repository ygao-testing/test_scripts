import pytest
import logging
import requests

from datetime import datetime, timezone
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response

logger = logging.getLogger(__name__)


@pytest.fixture(scope="package")
def get_explorer_time_range(api_v1_client):
    """Fixture to get the time range of the latest update"""
    query_card = QueryCard(api_v1_client)
    explorer_last_update = query_card.get_explorer_last_update()
    json_response = check_and_return_json_from_response(explorer_last_update)
    start_timestamp, end_timestamp = json_response['data'][0]['LATEST_START_TIME'], json_response['data'][0]['LATEST_END_TIME']
    start_datetime = datetime.fromtimestamp(
        start_timestamp/1000, tz=timezone.utc)
    start_datetime_str = start_datetime .strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    logger.info(f"Latest collection start time from Explorer API in ISO 8601 standard format: {
                start_datetime_str}")
    end_datetime = datetime.fromtimestamp(
        end_timestamp/1000, tz=timezone.utc)
    end_datetime_str = end_datetime .strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    logger.info(f"Latest collection end time from Explorer API in ISO 8601 standard format: {
                end_datetime_str}")
    return [start_datetime_str, end_datetime_str]


def compare_resource_ids(old_response: requests.Response, new_response: requests.Response):
    """
    Helper function to compare resource_ids returned by Old Explorer and New Explorer

    Args:
        old_response: Response from calling Explorer endpoints
        new_response: Response from calling ExplorerV2 endpoints

    """
    old_response = check_and_return_json_from_response(old_response)
    new_response = check_and_return_json_from_response(new_response)
    assert "errors" not in old_response, f"Expect no error returned, but got {old_response['errors'][0]['message']}"
    assert "errors" not in new_response, f"Expect no error returned, but got {new_response['errors'][0]['message']}"
    new_explorer_resource_ids = set(resource['node']['resourceId']
                                    for resource in new_response['data']['resources']['edges'])
    old_explorer_resource_ids = set(resource['node']['resourceId']
                                    for resource in old_response['data']['resources']['edges'])
    old_has_more_resource = old_explorer_resource_ids - new_explorer_resource_ids
    assert not old_has_more_resource, f"Expect New Explorer has more resources returned, but it missed {old_has_more_resource}"
