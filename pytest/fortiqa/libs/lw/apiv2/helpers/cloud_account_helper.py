from fortiqa.libs.lw.apiv2.api_client.cloud_accounts.cloud_accounts import CloudAccounts


class CloudAccountHelper:

    def __init__(self, user_api):
        self.user_api = user_api

    def get_all_cloud_accounts(self):
        """
        Retrieve all cloud accounts.

        This method sends a request to retrieve a list of all cloud accounts and
        ensures that the response has a status code of 200.
        """
        resp = CloudAccounts(self.user_api).list_all_cloud_accounts()
        assert resp.status_code == 200
        return resp

    def create_aws_cfg_cloud_account(self, payload: dict):
        """Create a new AWS Config cloud account."""
        resp = CloudAccounts(self.user_api).create_cloud_account(payload=payload)
        return resp

    def delete_cloud_account_integration(self, intg_guid: str):
        """This method sends a request to delete a cloud account integration using its integration GUID."""
        resp = CloudAccounts(self.user_api).delete_cloud_account(intgGuid=intg_guid)
        return resp
