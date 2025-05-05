from fortiqa.libs.lw.apiv2.api_client.lacework_resource import LaceworkResource
import json


class AlertRules(LaceworkResource):
    """
    Class to interact with Alert Rules in Lacework.

    This class inherits from LaceworkResource and initializes specific fields for Alert Rules.
    """

    def __init__(self, user_api, resource_payload=None) -> None:
        """
        Initialize the AlertRules with the user API and optional resource payload.

        :param user_api: The user API instance to interact with the Lacework API.
        :param resource_payload: Optional dictionary containing the alert profile payload.
        """
        super().__init__(user_api)
        self._api_url = f"{user_api.url}/AlertRules"
        self._resource_type = "Alert Rules"
        self._id_field = "mcGuid"
        if resource_payload:
            self._resource_id = resource_payload.get("mcGuid", "")
            # the name field is stored in alertProfileId by API.
            self._resource_name = resource_payload.get("filters", {}).get("name", "")
            self._resource_payload = resource_payload

    def find_id_by_name(self, resource_name):
        """
        Find the resource id by resource name.

        :param resource_name: Resource name to search for.
        :return: Resource ID if found, otherwise None.
        """
        response = self.list_all_resource()
        resources = json.loads(response.text)["data"]
        for resource in resources:
            if resource_name == resource.get("filters", {}).get("name", None):
                return resource[self._id_field]
        return ""
