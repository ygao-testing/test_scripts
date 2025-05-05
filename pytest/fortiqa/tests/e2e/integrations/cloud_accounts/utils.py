import json
from google.cloud import iam_admin_v1
from google.cloud import iam_credentials_v1
from google.oauth2 import service_account
from google.auth.transport import requests
import google.auth


def create_gcp_roles_w_permissions():
    """
    Creates three Google Cloud Platform (GCP) IAM roles with specific permissions.

    The function reads permissions from JSON files for three roles: cloudtrail, configuration, and agentless.
    It then creates these roles in the specified GCP project using the IAM client.
    """
    cloudtrail_permissions = json.loads(open('./e2e/integrations/cloud_accounts/data/policies/gcp_cloudtrail.json').read())
    configuration_permissions = json.loads(open('./e2e/integrations/cloud_accounts/data/policies/gcp_config.json').read())
    agentless_permissions = json.loads(open('./e2e/integrations/cloud_accounts/data/policies/gcp_agentless.json').read())

    cloudtrail_role = iam_admin_v1.Role(
        title="cloudtrail_role",
        description="cloudtrail_role",
        included_permissions=cloudtrail_permissions['permissions'],
        stage="GA",
    )

    configuration_role = iam_admin_v1.Role(
        title="configuration_role",
        description="configuration_role",
        included_permissions=configuration_permissions['permissions'],
        stage="GA",
    )

    agentless_role = iam_admin_v1.Role(
        title="agentless_role",
        description="agentless_role",
        included_permissions=agentless_permissions['permissions'],
        stage="GA",
    )

    client = iam_admin_v1.IAMClient()

    cloudtrail_request = iam_admin_v1.CreateRoleRequest(
        parent="projects/cnapp-445301",
        role_id="cloudtrail_role",
        role=cloudtrail_role
    )
    cloudtrail_response = client.create_role(request=cloudtrail_request)
    print("Cloudtrail role created", cloudtrail_response)

    configuration_request = iam_admin_v1.CreateRoleRequest(
        parent="projects/cnapp-445301",
        role_id="configuration_role",
        role=configuration_role
    )
    configuration_response = client.create_role(request=configuration_request)
    print("Configuration role created", configuration_response)

    agentless_request = iam_admin_v1.CreateRoleRequest(
        parent="projects/cnapp-445301",
        role_id="agentless_role",
        role=agentless_role
    )
    agentless_response = client.create_role(request=agentless_request)
    print("Agentless role created", agentless_response)


def delete_gcp_roles():
    """
    Deletes specific Google Cloud Platform (GCP) roles.

    This function deletes three roles in a GCP project:
    - Cloudtrail role
    - Configuration role
    - Agentless role

    It uses the IAMClient from the Google Cloud IAM Admin API to send delete requests for each role.
    After each role is deleted, a confirmation message is printed to the console.
    """
    client = iam_admin_v1.IAMClient()

    cloudtrail_request = iam_admin_v1.DeleteRoleRequest(
        name="projects/cnapp-445301/roles/cloudtrail_role"
    )
    cloudtrail_response = client.delete_role(request=cloudtrail_request)
    print("Cloudtrail role deleted", cloudtrail_response)

    configuration_request = iam_admin_v1.DeleteRoleRequest(
        name="projects/cnapp-445301/roles/configuration_role"
    )
    configuration_response = client.delete_role(request=configuration_request)
    print("Configuration role deleted", configuration_response)

    agentless_request = iam_admin_v1.DeleteRoleRequest(
        name="projects/cnapp-445301/roles/agentless_role"
    )
    agentless_response = client.delete_role(request=agentless_request)
    print("Agentless role deleted", agentless_response)


def generate_access_token():
    """
    Generates an access token for a specified service account.

    This function uses the IAMCredentialsClient from the Google Cloud IAM library
    to generate an access token for the service account specified in the request.

    Returns:
        str: The generated access token.
    """
    client = iam_credentials_v1.IAMCredentialsClient()

    request = iam_credentials_v1.GenerateAccessTokenRequest(
        name="projects/-/serviceAccounts/107409532572911400898",
        # delegates=["projects/-/serviceAccounts/107409532572911400898"],
        scope=["https://www.googleapis.com/auth/cloud-platform"],
    )
    response = client.generate_access_token(request=request)
    return response.access_token


CREDENTIAL_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def get_default_token():
    """
    Obtain a service account token using the default credentials file in env.

    This function retrieves the default credentials and project ID for the
    Google Cloud environment, refreshes the credentials to ensure they are
    up-to-date, and returns the authentication token.

    Returns:
        str: The authentication token for the default Google Cloud credentials.
    """
    credentials, project_id = google.auth.default(scopes=CREDENTIAL_SCOPES)
    credentials.refresh(requests.Request())
    return credentials.token


CREDENTIALS_KEY_PATH = './cloud_accounts/data/cnapp-445301-679c8b3d8350.json'


def get_service_account_token(credentials_key_path):
    """
    Obtain a service account token using the provided credentials file.

    This function reads the service account credentials from a file specified
    by credentials_key_path, refreshes the credentials to ensure they are
    up-to-date, and generates the access token.

    Args:
        credentials_key_path: str, the path to the service account credentials file

    Returns:
        str: The access token for the service account.
    """
    CREDENTIAL_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
    credentials = service_account.Credentials.from_service_account_file(
            credentials_key_path, scopes=CREDENTIAL_SCOPES)
    credentials.refresh(requests.Request())
    return credentials.token
# print(get_service_account_token(CREDENTIALS_KEY_PATH))
