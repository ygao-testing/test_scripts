from fortiqa.libs.lw.apiv2.api_client.lacework_resource import LaceworkResource


class Policies(LaceworkResource):
    """
    Class to interact with Policies in Lacework.

    This class inherits from LaceworkResource and initializes specific fields for Policies resource.
    """

    def __init__(self, user_api, resource_payload=None) -> None:
        """
        Initialize the Policies with the user API and optional resource payload.

        :param user_api: The user API instance to interact with the Lacework API.
        :param resource_payload: Optional dictionary containing the alert profile payload.
        """
        super().__init__(user_api)
        self._api_url = f"{user_api.url}/Policies"
        self._resource_type = "Policies"
        self._id_field = "policyId"
        if resource_payload:
            self._resource_id = resource_payload.get("policyId", "")
            self._resource_name = resource_payload.get("title", "")
            self._resource_payload = resource_payload

    def delete_resource(self, resource_id=None, resource_name=None):
        """
        Delete a resource by specifying the resource id.
        Override the parent method to delete a resource by the title field.
        """
        if resource_id is None and resource_name is None:
            raise ValueError("Either resource_id or resource_name must be provided.")
        if resource_id is None:
            resource_id = self.find_id_by_title(resource_name or self._resource_name)
        return super().delete_resource(resource_id)
