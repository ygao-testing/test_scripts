import copy
import logging

from datetime import datetime, timedelta
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard

logger = logging.getLogger(__name__)


def test_investigate_identity_v1(api_v1_client):
    """
    This test case is to automate LINK-3292. It simulates customer clicking Identity->Top Identity->Investigate

    Given: The API V1 client for interacting with the Lacework
    When: Execute CIEM_Identities_RecalculatingInventoryTable, CIEM_IdentityDetails_RecentAssessmentsByIdentityUrn and CIEM_IdentityMetrics_EntitlementsUsageByIdentityUrn cards
    Then: All API responses should have a 200 status code

    Args:
        api_v1_client: API V1 client for interacting with the Lacework.
    """
    query_card_api = QueryCard(api_v1_client)
    current_time = datetime.now()
    seven_days_ago = current_time - timedelta(days=7)
    tomorrow = current_time + timedelta(days=1)
    payload = {
        "ParamInfo": {
            "StartTimeRange": int(seven_days_ago.timestamp()),
            "EndTimeRange": int(tomorrow.timestamp()),
            "EnableEvalDetailsMView": True
        },
        "Filters": {}
    }
    identities_order_by_risk_resp = query_card_api.exec_query_card(card_name="CIEM_Identities_RecalculatingInventoryTable", payload=payload)
    assert identities_order_by_risk_resp.status_code == 200, f"Fail to execute card CIEM_Identities_RecalculatingInventoryTable, err: {identities_order_by_risk_resp.text}"
    identities_order_by_risk = identities_order_by_risk_resp.json()['data']
    if not identities_order_by_risk:
        logger.info("There is no identity inside Lacework")
    else:
        top_rist_identity = identities_order_by_risk[0]
        logger.info(f"Top risk identity: {top_rist_identity}")
        recalculate_by_urn_payload = copy.deepcopy(payload)
        recalculate_by_urn_payload['ParamInfo']['IdentityUrn'] = top_rist_identity['IDENTITY_URN']
        recalculate_by_urn_resp = query_card_api.exec_query_card(card_name="CIEM_IdentityDetails_RecalculatingIdentitySummaryByIdentityUrn", payload=recalculate_by_urn_payload)
        assert recalculate_by_urn_resp.status_code == 200, f"Fail to execute card CIEM_IdentityDetails_RecalculatingIdentitySummaryByIdentityUrn, err: {recalculate_by_urn_resp.text}"
        investigate_by_urn_resp = query_card_api.exec_query_card(card_name="CIEM_IdentityMetrics_EntitlementsUsageByIdentityUrn", payload=recalculate_by_urn_payload)
        assert investigate_by_urn_resp.status_code == 200, f"Fail to execute card CIEM_IdentityMetrics_EntitlementsUsageByIdentityUrn, err: {investigate_by_urn_resp.text}"
