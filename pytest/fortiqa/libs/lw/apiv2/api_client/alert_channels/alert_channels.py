from fortiqa.libs.lw.apiv2.api_client.lacework_resource import LaceworkResource


class AlertChannels(LaceworkResource):
    """
    API client class to interact with Alert Channels in Lacework.
    Inherits from LaceworkResource and initializes specific fields for Alert Channels endpoints.
    """

    def __init__(self, user_api, resource_payload=None) -> None:
        super().__init__(user_api)
        self._api_url = f"{user_api.url}/AlertChannels"
        self._resource_type = "Alert Channels"
        self._id_field = "intgGuid"
        if resource_payload:
            self._resource_id = resource_payload.get("intgGuid", "")
            self._resource_payload = resource_payload
            self._resource_name = resource_payload.get("name", "")
