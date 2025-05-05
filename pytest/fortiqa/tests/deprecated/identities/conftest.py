import pytest

from datetime import datetime, timedelta
from collections import defaultdict

from fortiqa.libs.lw.apiv2.helpers.query_helper import QueryHelper


@pytest.fixture
def list_all_identities(api_v2_client):
    """
    Fixture to create and execute a query to list all identities from 7 days ago until tomorrow .

    This fixture creates a Lacework Query Language (LQL) query that fetches identity data, such as
    NAME, PRINCIPAL_ID, risks, risk_severity, risk_score and TAGS.

    Yields:
        dict: A dictionary containing the result of the query, which includes identities data.

    Cleanup:
        After yielding the response, the query is deleted using `delete_query_by_id`.
    """
    query_helper = QueryHelper(api_v2_client)
    query_id = "list_all_identities1"
    query_helper.create_query(query_text="{ source { LW_CE_IDENTITIES, ARRAY_TO_ROWS(METRICS:risks) as risks } return { NAME, PRINCIPAL_ID, METRICS:risks as risks, METRICS:risk_severity::String as severity, METRICS:risk_score::String as risk_score, TAGS } }",
                              query_id=query_id)
    current_time = datetime.now()
    seven_days_ago = current_time - timedelta(days=7)
    tomorrow = current_time + timedelta(days=1)
    seven_days_ago_str = seven_days_ago.strftime('%Y-%m-%d')
    tomorrow_str = tomorrow.strftime('%Y-%m-%d')
    query_response = query_helper.execute_query_by_id(query_id=query_id, start_time_range=seven_days_ago_str, end_time_range=tomorrow_str).json()
    yield query_response
    query_helper.delete_query_by_id(query_id=query_id)


@pytest.fixture
def categorize_identities(list_all_identities):
    """
    This fixture processes the list of identities and categorizes them into different
    AWS-related categories, such as IAM users, service-linked roles, IAM roles, and instance profiles.

    Returns:
        dict: A categorized dictionary of AWS identities, where identities are categorized
              under 'iam_user', 'service_linked_role', 'iam_role', and 'instance_profile'.
    """
    identities = defaultdict(lambda: defaultdict(dict))
    for identity in list_all_identities['data']:
        if identity.get('PRINCIPAL_ID', None) and 'aws' in identity['PRINCIPAL_ID']:
            arn = identity['PRINCIPAL_ID']
            if 'user' in arn:
                identities['aws']['iam_user'][arn] = identity
            elif 'aws-service-role' in arn:
                identities['aws']['service_linked_role'][arn] = identity
            elif 'role' in arn:
                identities['aws']['iam_role'][arn] = identity
            elif 'instance-profile' in arn:
                identities['aws']['instance_profile'][arn] = identity
    return identities
