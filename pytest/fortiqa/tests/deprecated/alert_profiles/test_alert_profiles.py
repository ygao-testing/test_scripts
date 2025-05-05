import json
import logging

from fortiqa.libs.lw.apiv2.api_client.alert_profiles.alert_profiles import AlertProfiles

logger = logging.getLogger(__name__)


class TestAlertProfiles:

    def test_tf_alert_profiles(self, api_v2_client, tf_lw_alert_profiles):
        """Verify alert profiles created using lacework TF provider are returned by LW API.

        Given: List of alert profiles pre-deployed with terraform.
        When: Listing existing alert profiles using LW API.
        Then: Alert profiles deployed by terraform should be found in the list returned by API.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework.
            tf_lw_alert_profiles: list of alert rules deployed with terraform.
        """
        resp = AlertProfiles(api_v2_client).get_alert_profiles()
        alert_profiles_from_api = json.loads(resp.text)['data']

        not_found = []

        for alert_profile in tf_lw_alert_profiles:
            found = False
            for api_alert_profile in alert_profiles_from_api:
                if alert_profile['name'] == api_alert_profile['alertProfileId'] and all(alert in api_alert_profile['alerts'] for alert in alert_profile['alerts']):
                    found = True
            if not found:
                not_found.append(alert_profile)
        assert len(not_found) == 0, f'Alert rules {not_found} were not in API response {alert_profiles_from_api}'
