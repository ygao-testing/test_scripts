import json
import logging

from fortiqa.libs.lw.apiv2.api_client.alert_rules.alert_rules import AlertRules

logger = logging.getLogger(__name__)


class TestAlertRules:

    def test_tf_alert_rules(self, api_v2_client, tf_lw_alert_rules):
        """Verify alert rules created using lacework TF provider are returned by LW API.

        Given: List of alert rules pre-deployed with terraform.
        When: Listing existing alert rules using LW API.
        Then: Alert rules deployed by terraform should be found in the list returned by API.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework.
            tf_lw_alert_rules: list of alert rules deployed with terraform.
        """
        resp = AlertRules(api_v2_client).list_all_alert_rules()
        alert_rules_from_api = json.loads(resp.text)['data']
        logger.info(f'{alert_rules_from_api=}')
        not_found = []
        logger.info(f'{tf_lw_alert_rules=}')
        for alert_rule in tf_lw_alert_rules:
            found = False
            for api_alert_rule in alert_rules_from_api:
                if (alert_rule['name'] == api_alert_rule['filters']['name']
                        and alert_rule['alert_channels'] == api_alert_rule['intgGuidList']):
                    found = True
            if not found:
                not_found.append(alert_rule)
        assert len(not_found) == 0, f'Alert rules {not_found} were not in API response {alert_rules_from_api}'
