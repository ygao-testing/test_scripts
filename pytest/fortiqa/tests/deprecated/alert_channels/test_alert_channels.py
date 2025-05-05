import json
import logging

from fortiqa.libs.lw.apiv2.api_client.alert_channels.alert_channels import AlertChannels


logger = logging.getLogger(__name__)


class TestAlertChannels:

    def test_tf_email_alert_channels(self, api_v2_client, tf_lw_email_alert_channels):
        """Verify email alert channels created using lacework_alert_channel_email of the lacework TF provider are returned by LW API.

        Given: List of email alert channels pre-deployed with terraform.
        When: Listing existing email alert channels using LW API.
        Then: Email alert channels deployed by terraform should be found in the list returned by API.

        Args:
            api_v2_client: API V2 client for interacting with the Lacework.
            tf_lw_email_alert_channels: list of email alert channels deployed with terraform.
        """
        resp = AlertChannels(api_v2_client).list_all_alert_channels()
        logger.info(f'{tf_lw_email_alert_channels=}')
        alert_channels_from_api = json.loads(resp.text)['data']
        logger.info(f'{alert_channels_from_api=}')
        not_found = []
        for email_alert_channel in tf_lw_email_alert_channels:
            found = False
            for api_alert_channel in alert_channels_from_api:
                if (email_alert_channel['name'] == api_alert_channel['name']
                        and ','.join(email_alert_channel['recipients']) == api_alert_channel['data']['channelProps']['recipients']
                        and email_alert_channel['intg_guid'] == api_alert_channel['intgGuid']):
                    found = True
            if not found:
                not_found.append(email_alert_channel)
        assert len(not_found) == 0, f'Email alert channels {not_found} were not in API response {alert_channels_from_api}'
