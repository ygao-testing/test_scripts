from fortiqa.libs.lw.apiv2.api_client.lacework_resource import LaceworkResource


class AlertProfiles(LaceworkResource):
    """
    Class to interact with Alert Profiles in Lacework.

    This class inherits from LaceworkResource and initializes specific fields for Alert Profiles.
    """

    def __init__(self, user_api, resource_payload=None) -> None:
        """
        Initialize the AlertProfiles with the user API and optional resource payload.

        :param user_api: The user API instance to interact with the Lacework API.
        :param resource_payload: Optional dictionary containing the alert profile payload.
        """
        super().__init__(user_api)
        self._api_url = f"{user_api.url}/AlertProfiles"
        self._resource_type = "Alert Profile"
        self._id_field = "alertProfileId"
        if resource_payload:
            self._resource_id = resource_payload["alertProfileId"]
            # the name field is stored in alertProfileId by API.
            self._resource_name = resource_payload.get("alertProfileId", "")
            self._resource_payload = resource_payload
