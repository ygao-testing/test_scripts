"""Onboarding tests"""
import random
import secrets
import string

agentless_allregions = [
    "ap-south-1",
    "eu-north-1",
    "eu-west-3",
    "eu-west-2",
    "eu-west-1",
    "ap-northeast-3",
    "ap-northeast-2",
    "ap-northeast-1",
    "ca-central-1",
    "sa-east-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "eu-central-1",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2"
]

integration_ui_mapping = {
    'aws_agentless': 'Agentless Workload Scanning',
    'aws_config': 'Configuration',
    'aws_cloudtrail': 'CloudTrail',
}


def generate_aws_credentials():
    """
    Generate Random AWS Credentials
    :return: invalid Access key ID,Secret access key,Session token
    """
    access_key = 'AKIA' + ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    secret_access_key = ''.join(secrets.choice(string.ascii_letters + string.digits + '/+=') for _ in range(40))
    session_token = ''.join(secrets.choice(string.ascii_letters + string.digits + '/+=') for _ in range(356))
    return [access_key, secret_access_key, session_token]


# AWS #
def test_aws_discovery_error_with_invalid_data(ui):
    """
    Test AWS accounts automated integration with valid AWS role credentials
    Oriole Test Cases:
        1204334 Open 'Settings' page from the left menu
        1204335 Direct to the correct URL when clicking the left menu
        1204336 Left menu item should be active and highlighted when on the specified page
        1204337 Open 'Onboarding' page from the Settings menu
        1204338 Open 'Configure cloud accounts' page in the Onboarding page
        1204339 Direct to the correct URL when clicking the 'Configure cloud accounts'
        1204340 Open 'New cloud integration-Automated configuration' page from "Integrate cloud account" page
        1204341 "Next" button
        1204355 [Invalid credential] Discovery should fail if AWS credential is invalid
        1204342 [Invalid credential] Show discovery error text if AWS credential is invalid
        1204343 [Invalid credential] "Back" button is enabled
        1204344 [Invalid credential] "Integrate" button is disabled
    """
    invalid_aws_credentials = generate_aws_credentials()
    integration_data = {
        "integration_method": integration_ui_mapping[random.choice(['aws_agentless', 'aws_config', 'aws_cloudtrail'])],
        "access_key_id": invalid_aws_credentials[0],
        "secret_access_key": invalid_aws_credentials[1],
        "session_token": invalid_aws_credentials[2],
        "default_region": "us-east-1",
    }
    ui.settings_onboarding.aws_integration_with_invalid_data(integration_data)


def test_aws_discovery_error_with_empty_aws_credentials(ui):
    """
    Test AWS accounts automated integration with valid AWS role credentials
    Oriole Test Cases:
        1204345 [Empty credential] Show error text if Access key ID is not provided
        1204346 [Empty credential] Show error text if Secret access key is not provided
        1204347 [Empty credential] Show error text if Session token is not provided
        1204348 [Empty credential] Show error text if Default Region is not provided
        1204349 [Empty credential] "Cancel" button is enabled
        1204350 [Empty credential] "Next" button is enabled
    """
    integration_data = {
        "integration_method": integration_ui_mapping[random.choice(['aws_agentless', 'aws_config', 'aws_cloudtrail'])],
        "access_key_id": "",
        "secret_access_key": "",
        "session_token": "",
        "default_region": "",
    }
    ui.settings_onboarding.aws_integration_with_empty_data(integration_data)


def test_aws_discovery_error_with_empty_integration_method(ui):
    """
    Test AWS accounts automated integration with valid integration method
    Oriole Test Cases:
        1204356 [Empty method] Discovery should fail if Integration Method is not provided
        1204351 [Empty method] Show discovery error text if Integration Method is not provided
        1204352 [Empty method] "Back" button is enabled
        1204353 [Empty method] "Integrate" button is disabled
    """
    invalid_aws_credentials = generate_aws_credentials()
    integration_data = {
        "integration_method": "",
        "access_key_id": invalid_aws_credentials[0],
        "secret_access_key": invalid_aws_credentials[1],
        "session_token": invalid_aws_credentials[2],
        "default_region": "us-east-1",
    }
    ui.settings_onboarding.aws_integration_with_empty_data(integration_data, empty_method=True)
