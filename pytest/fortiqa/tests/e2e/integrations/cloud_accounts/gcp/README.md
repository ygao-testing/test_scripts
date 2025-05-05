## Creating a Service Account

1. Log in to the Google Cloud Console (https://console.cloud.google.com/).
2. Select your project from the top dropdown menu.
3. Navigate to "IAM & Admin" > "Service Accounts" in the left sidebar.
4. Click on "+ CREATE SERVICE ACCOUNT" at the top of the page1.
5. Enter a name for your service account, an ID (which will be generated automatically), and an optional description.
6. Click "Create" to proceed.


## Obtaining Service Account Keys


1. After creating the service account, click on its email address in the service accounts list.
2. Go to the "Keys" tab.
3. Click "Add Key" > "Create new key".
4. Select "JSON" as the key type and click "Create".
5. The JSON key file will be automatically downloaded to your computer. Keep this file secure, as it cannot be downloaded again.

## Add Service Account Keys in user_config.yaml
1. copy and paste the credentials to user_config.yaml

## Creating Organization-Level Roles
1. Go to organization dashboard.
2. Navigate to "IAM & Admin" > "Roles" in the left sidebar.
3. Click on "+ CREATE ROLE" at the top of the page.
4. Provide a title and description for the role.
5. Add permissions to the role based on your requirements.

## Assigning Roles to the Service Account
1. Go to organization dashboard.
2. Go to "IAM & Admin" > "IAM" in the left sidebar.
3. Click on "+ ADD" at the top of the page.
4. In the "New members" field, enter the email address of your service account.
5. Click on the "Select a role" dropdown and choose the roles you want to assign.
6. Click "Save" to apply the changes.


## Instructions to run gcp test
`cd fortiqa/pytest/fortiqa/tests`

`pytest integrations/cloud_accounts/gcp/test_gcp_self_deployment.py`
