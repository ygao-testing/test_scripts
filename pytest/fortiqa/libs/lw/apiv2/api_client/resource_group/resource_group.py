from fortiqa.libs.lw.apiv2.api_client.lacework_resource import LaceworkResource


class ResourceGroup(LaceworkResource):
    """
    Class to interact with Resource Group in Lacework.

    This class inherits from LaceworkResource and initializes specific fields for Resource Group endpoints.
    """

    def __init__(self, user_api, resource_payload=None) -> None:
        """
        Initialize the ResourceGrouop with the user API and optional resource payload.

        :param user_api: The user API instance to interact with the Lacework API.
        :param resource_payload: Optional dictionary containing the alert profile payload.
        """
        super().__init__(user_api)
        self._api_url = f"{user_api.url}/ResourceGroups"
        self._resource_type = "Resource Groups"
        self._id_field = "resourceGroupGuid"
        if resource_payload:
            self._resource_id = resource_payload.get("resourceGroupGuid", "")
            self._resource_payload = resource_payload
            self._resource_name = resource_payload.get("name", "")
