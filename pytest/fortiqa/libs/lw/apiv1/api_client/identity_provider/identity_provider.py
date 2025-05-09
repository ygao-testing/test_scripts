import logging
import requests
logger = logging.getLogger(__name__)


class IdentityProviderV1:
    """This class provides methods to interact with the identity provider API."""
    def __init__(self, api_v1_client) -> None:
        self._user_api = api_v1_client
        self._base_url = f"{api_v1_client.url}/integrations/identityProviders"

    def get_identity_providers(self) -> requests.Response:
        """
        Get all identity providers.

        :return: requests.Response object
        """
        response = self._user_api.get(self._base_url)
        return response

    def delete_identity_provider(self, id: str) -> requests.Response:
        """
        Delete an identity provider by ID.

        :param id: ID of the identity provider to delete
        :return: requests.Response object
        """
        response = self._user_api.delete(f"{self._base_url}/{id}")
        return response

    def integrate_identity_provider(self, payload: dict) -> requests.Response:
        """
        Integrate an identity provider.

        :param payload: Payload to integrate the identity provider with
        :return: requests.Response object

        payload example:
        {
            "TYPE": "GOOGLE_IDENTITY",
            "ENABLED": 1,
            "IS_ORG": 0,
            "NAME": "NAME of the identity provider",
            "DATA": {
                "CREDENTIALS": {
                    "CLIENT_ID": "REQUIRED from creds.json",
                    "PRIVATE_KEY_ID": "REQUIRED from creds.json",
                    "CLIENT_EMAIL": "REQUIRED from creds.json",
                    "PRIVATE_KEY": "REQUIRED from creds.json"
                },
                "CUSTOMER_ID": "REQUIRED"
            }
        }
        response example:
        {
            "data": [
                {
                    "INTG_GUID": "FORTIQAE_2BE56717727E33C360A1565BF6AD164C4F248084793B994",
                    "NAME": "Lacework CIEM GCP",
                    "CREATED_OR_UPDATED_TIME": 1745003638049,
                    "CREATED_OR_UPDATED_BY": "zqi@fortinet.com",
                    "ENV_GUID": "FORTIQA_849FBED9E6BB436608AB8B588E0AC1DC39F835D7E598F3B8",
                    "TYPE": "GOOGLE_IDENTITY",
                    "ENABLED": 1,
                    "STATE": {
                        "ok": true,
                        "lastUpdatedTime": 1745003637999,
                        "lastSuccessfulTime": 1745003637999,
                        "details": {}
                    },
                    "IS_ORG": 0,
                    "DATA": {
                        "CREDENTIALS": {
                            "CLIENT_ID": "114278914745252704551",
                            "CLIENT_EMAIL": "admin-console-privileges@cnapp-445301.iam.gserviceaccount.com",
                            "PRIVATE_KEY_ID": "dc5a729a1ee0018571d86f30b345f4dfc873e931"
                        },
                        "CUSTOMER_ID": "C00tdsonw"
                    }
                }
            ],
            "ok": true,
            "message": "SUCCESS"
        }
        """
        response = self._user_api.post(self._base_url, payload=payload)
        return response
