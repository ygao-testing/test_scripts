import pytest
import time
import logging
import string
import os
import random
import tftest
from datetime import datetime, timedelta, timezone
from fortiqa.tests.e2e.ingestion.azure.tf_modules import e2e_resource_inventory_tf_modules
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response


logger = logging.getLogger(__name__)

random_id = ''.join(random.choices(string.ascii_letters, k=4)).lower()
tf_owner_prefix = f'e2e-ingestion-test-{random_id}'


@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session):
    """Check if TF_VAR_PUBLIC_KEY environment variable is set and raise an error if not."""
    public_key_var = "TF_VAR_PUBLIC_KEY"

    if not os.environ.get(public_key_var):
        raise RuntimeError(
            f"The environment variable {public_key_var} is not set. "
            "Please set it before running the tests."
        )
    else:
        logger.info(f"{public_key_var} is already set.")


def pytest_addoption(parser):
    """Adds a command-line option '--not_use_ingestion_tag_azure' for pytest.

    By default, the option is False, meaning the ingestion tag is used to filter Azure resources.
    When the '--not_use_ingestion_tag_azure' flag is specified, it sets the option to True,
    disabling filtering by the ingestion tag.

    Args:
        parser: The pytest command-line parser object.
    """
    parser.addoption(
        "--not_use_ingestion_tag_azure",
        action="store_true",
        default=False,
        help="For ingestion-related test cases: disable filtering Azure resources by the ingestion tag. "
             "By default (flag not provided), the tag is used to filter resources."
    )


@pytest.fixture(scope="session")
def ingestion_tag(request):
    """Fixture to generate a dynamic ingestion tag used for filtering azure resources.

    This fixture generates a unique ingestion tag with the key 'Test', combining the 'tf_owner_prefix'
    (used as the 'Owner' tag for AWS resource deployment) and a UTC timestamp in ISO 8601 format
    with milliseconds and 'Z' appended. The tag helps identify and filter Azure resources deployed
    during tests.

    Behavior:
        - By default, the fixture generates and returns the dynamic ingestion tag.
        - If the '--not_use_ingestion_tag_azure' command-line option is provided, the fixture returns None,
          disabling ingestion tag filtering.

    Key Components:
        - 'tf_owner_prefix': Used as the Owner tag for Azure resources.
        - ISO 8601 UTC timestamp: Ensures each tag is unique across test runs.

    Command-Line Option:
        --not_use_ingestion_tag_azure: When specified, disables the ingestion tag and returns None.

    Returns:
        dict[str, str] | None: A dictionary containing the ingestion tag.
            Example:
                {"Test": "e2e-ingestion-test-abc123-2024-12-16T07:29:06.263Z"}

            If '--not_use_ingestion_tag_azure' is set:
                None
    """
    if request.config.getoption("not_use_ingestion_tag_azure"):
        return None
    else:
        # Format the UTC timestamp in ISO 8601 format with milliseconds and 'Z'
        utc_now = datetime.now(timezone.utc)

        # Format the UTC timestamp in ISO 8601 format with milliseconds and 'Z'
        formatted_timestamp = utc_now.strftime(
            "%Y-%m-%dT%H:%M:%S") + f".{utc_now.microsecond // 1000:03d}Z"
        return {"Test": f'{tf_owner_prefix}-{formatted_timestamp}'}


@pytest.fixture(scope='session')
def time_filter():
    """Fixture to generate a time filter for use in tests.

    This fixture returns a dictionary with 'startTime' and 'endTime' keys.
    The 'startTime' is set to 24 hours before the current UTC time,
    and the 'endTime' is the current UTC time.

    Returns:
        dict: A dictionary containing 'startTime' and 'endTime'
              Example:
              {
                  "startTime": "2024-11-04T10:30:00Z",
                  "endTime": "2024-11-05T10:30:00Z"
              }
    """
    # Get the current time in UTC
    current_utc_time = datetime.now(timezone.utc)

    # Calculate the last day time by subtracting one day from the current time
    last_day_utc_time = current_utc_time - timedelta(days=1)

    # Format the current time and the last day time in the desired format
    formatted_current_utc_time = current_utc_time.strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    formatted_last_day_utc_time = last_day_utc_time.strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    return {
        "startTime": formatted_last_day_utc_time,
        "endTime": formatted_current_utc_time
    }


@pytest.fixture(scope='session')
def e2e_azure_tf_root(request) -> str:
    """Fixture returns root folder for azure e2e test lacework provider TF modules."""
    root = os.path.join(request.config.rootdir, '../terraform/e2e/azure/')
    logger.info(f'{root=}')
    return root


@pytest.fixture(scope='session')
def aws_env_variables(aws_account) -> None:
    """Fixture sets and deletes AWS credentials as env variables."""
    os.environ['AWS_ACCESS_KEY_ID'] = aws_account.aws_access_key_id
    os.environ['AWS_SECRET_ACCESS_KEY'] = aws_account.aws_secret_access_key
    yield
    del os.environ['AWS_ACCESS_KEY_ID']
    del os.environ['AWS_SECRET_ACCESS_KEY']


@pytest.fixture(scope="session")
def wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_azure(api_v1_client, wait_for_daily_collection_completion_azure) -> dict[str, str] | None:
    """Pytest fixture that waits for the Explorer's latest update time to be updated post daily ingestion completion for Azure.

    This fixture uses the 'api_v1_client' and the 'wait_for_daily_collection_completion_Azure' fixture to monitor the Explorer's
    latest update timestamps ('LATEST_START_TIME' and 'LATEST_END_TIME'). It begins monitoring from the ingestion completion
    end time ('endTime') provided by the 'wait_for_daily_collection_completion_Azure' fixture. It periodically queries the Explorer
    API to ensure that the timestamps fall within the specified ingestion timeframe. If the update occurs within 90 minutes,
    it returns a dictionary containing the start and end timestamps in ISO 8601 format, along with the actual timestamp when the
    update was detected.

    If the specified monitoring timeframe (90 minutes) has already elapsed when the fixture starts, it raises a 'TimeoutError'.
    Similarly, if the timestamps are not updated within 90 minutes of monitoring, it also raises a 'TimeoutError'.

    Args:
        api_v1_client: Fixture providing an instance of 'ApiV1Client' for interacting with the Lacework API v1.
        wait_for_daily_collection_completion_azure: Fixture ensuring daily ingestion collection is completed and providing
                                                  the ingestion timeframe.

    Returns:
        dict[str, str] | None: A dictionary with the latest update period:
                                {
                                    "startTime": "ISO 8601 start time",
                                    "endTime": "ISO 8601 end time",
                                    "actual_explorer_update": "Actual timestamp when the Explorer update was detected in ISO 8601 format"
                                }
                               If updated successfully.

    Raises:
        TimeoutError: Raised in two cases:
                      1. If the maximum wait time of 90 minutes after the actual collection completion has already elapsed when the fixture starts.
                      2. If the latest update timestamps are not updated within 90 minutes of monitoring.
    """
    time_filter = wait_for_daily_collection_completion_azure
    max_wait = 90  # minutes
    query_api = QueryCard(api_v1_client)
    is_within_range = False
    daily_collection_start_time_str = time_filter["startTime"]
    daily_collection_actual_completion_end_time_str = time_filter["endTime"]
    start_time = datetime.fromisoformat(
        daily_collection_actual_completion_end_time_str.replace("Z", "+00:00"))
    logger.info(f"Using the actual collection completion end time as the start time for monitoring Explorer updates: {
                start_time}")
    if (datetime.now(timezone.utc) - start_time) > timedelta(minutes=max_wait):
        raise TimeoutError(f"The maximum wait time of {
                           max_wait} minutes after the actual collection completion has elapsed.")

    while not is_within_range and (datetime.now(timezone.utc) - start_time) < timedelta(minutes=max_wait):
        response = query_api.get_explorer_last_update()
        assert response.status_code == 200, f"Expected 200 status code but actual {
            response.status_code}"
        response_json = check_and_return_json_from_response(response)
        logger.info(f"Raw response JSON from Explorer API to get last update: {
                    response_json}")
        last_update = response_json['data'][0]['LATEST_END_TIME']
        latest_start_time = response_json['data'][0]["LATEST_START_TIME"]
        logger.info(f"Latest collection end time from Explorer API in timestamp (milliseconds): {
                    last_update}")
        last_update_dt_utc = datetime.fromtimestamp(
            last_update/1000, tz=timezone.utc)
        last_update_str = last_update_dt_utc .strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        logger.info(f"Latest collection end time from Explorer API in ISO 8601 standard format: {
                    last_update_str}")
        latest_start_time_dt_utc = datetime.fromtimestamp(
            latest_start_time/1000, tz=timezone.utc)
        latest_start_time_str = latest_start_time_dt_utc .strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        is_within_range = daily_collection_start_time_str < last_update_str <= daily_collection_actual_completion_end_time_str
        if not is_within_range:
            logger.info(
                "Sleeping for 60 seconds before retrying to get Explorer's latest update end time.")
            time.sleep(60)

    time_diff = datetime.now(timezone.utc) - datetime.fromisoformat(
        daily_collection_actual_completion_end_time_str.replace("Z", "+00:00"))
    if is_within_range:
        logger.debug(f"explrer latest update time get updated {
                     time_diff.total_seconds()} seconds post collection completion")
        latest_update_period = {
            "startTime": latest_start_time_str,
            "endTime": last_update_str,
            "actual_explorer_update": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        }
        logger.debug(f"Latest update time period: {latest_update_period}")
        logger.info("Sleeping for 5 minutes to populate data after detecting the latest update time from Explorer.")
        time.sleep(300)
        return latest_update_period

    else:
        raise TimeoutError(f"Explorer latest update did not get updated in {
                           max_wait} minutes after ingestion completion.")


@pytest.fixture(scope='session')
def azure_env_variables(azure_account) -> None:
    """Fixture sets and deletes Azure credentials as env variables."""
    os.environ['ARM_SUBSCRIPTION_ID'] = azure_account.subscription_id
    os.environ['ARM_CLIENT_ID'] = azure_account.client_id
    os.environ['ARM_CLIENT_SECRET'] = azure_account.client_secret
    os.environ['ARM_TENANT_ID'] = azure_account.tenant_id
    yield
    del os.environ['ARM_SUBSCRIPTION_ID']
    del os.environ['ARM_CLIENT_ID']
    del os.environ['ARM_CLIENT_SECRET']
    del os.environ['ARM_TENANT_ID']


def apply_tf_modules(module_list: list[str], module_root: str, bucket_name: str, region: str, env: str, tags: dict | None = None) -> dict[str, dict]:
    """Deploys a list of Terraform modules with dynamic backend configuration and resource tagging.

    This function initializes and applies Terraform modules dynamically. A unique backend state file
    key is generated using the  env , 'tf_owner_prefix', module name, and a timestamp. By default, the 'OWNER'
    tag is applied to all Azure resources, while custom ingestion tags can optionally be provided
    for distinguishing deployments.

    Args:
        module_list (list[str]): List of Terraform module paths to be deployed.
        module_root (str): Root folder where all Terraform modules are located.
        bucket_name (str): Name of the S3 bucket used for Terraform backend state storage.
        region (str): Azure region where the S3 bucket resides.
        env (str): The environment in which the tests are run. For example, "fortiqa" or
                   "fortiqa.spork.corp".
        tags (dict | None): Optional custom tags to distinguish ingestion runs.

    Returns:
        dict[str, dict]: A dictionary containing module deployment details, where each key is a module name,
                         and the value contains:
                         - 'tf': The TerraformTest instance for the module.
                         - 'deployment_time': A monotonic timestamp captured **after deployment completes**.
                         - 'deployment_timestamp': The local system time recorded **after deployment completes**.
    """
    hosts = {}
    # Format the UTC timestamp in ISO 8601 format with milliseconds and 'Z'
    utc_now = datetime.now(timezone.utc)

    # Format the UTC timestamp in ISO 8601 format with milliseconds and 'Z'
    formatted_timestamp = utc_now.strftime(
        "%Y-%m-%dT%H:%M:%S") + f".{utc_now.microsecond // 1000:03d}Z"
    for tf_module in module_list:
        tf = tftest.TerraformTest(tf_module, module_root)
        try:
            # Generate a dynamic key for the state file
            dynamic_key = f"ingestion/{env}/azure/test_{tf_owner_prefix}_{
                formatted_timestamp}/{tf_module}/terraform.tfstate"
            logger.info(f"dynamic_key={dynamic_key}")

            # Setup with dynamic backend configuration
            backend_config = {
                "bucket": bucket_name,
                "key": dynamic_key,
                "region": region,
                "encrypt": "true"
            }
            logger.debug(f"Backend configuration: {backend_config}")
            tf_vars = {
                'OWNER': tf_owner_prefix
            }
            # Pass the tags if provided
            if tags:
                tf_vars['INGESTION_TAG'] = tags
            logger.info(f"Initializing terraform for  {tf_module} module")
            tf.setup(init_vars=backend_config)
            logger.info(f"Deploying resources for  {tf_module} module")
            # Run terraform apply and capture the output
            apply_output = tf.apply(tf_vars=tf_vars, capture_output=True)
            logger.info(f"Terraform apply output for module '{
                        tf_module}':\n{apply_output}")

            # Check for any errors in the output
            if "Error" in apply_output or "Failed" in apply_output:
                logger.error(f"Partial failure detected in module '{
                             tf_module}'. Output:\n{apply_output}")

        except Exception as e:
            logger.exception(f'Failed to deploy TF module {
                             tf_module} error: {e}')
        finally:
            hosts[tf_module] = {
                'tf': tf,
                'deployment_time': time.monotonic(),
                'deployment_timestamp': datetime.now(),
            }
    return hosts


def destroy_tf_modules(tf_modules: dict) -> None:
    """Destroys the Terraform modules.
    Args:
        tf_modules: Dictionary containing Terraform modules information.
    """
    for tf_module in tf_modules:
        try:
            logger.info(f'Destroying {tf_module=}')
            tf_modules[tf_module]['tf'].destroy(tf_vars={
                'OWNER': tf_owner_prefix
            })
        except Exception:
            logger.exception(f'Failed to destroy TF module {tf_module}')


def pytest_configure(config):
    """
    Pytest configuration hook to initialize tracking variables for Terraform resource management.

    Tracks multiple resource groups:
        - '_tf_inventory_hosts': Tracks 'inventory' Terraform modules.
        - '_tf_graphql_hosts': Tracks 'graphql' Terraform modules.
        - '_tf_inventory_destroyed': Indicates if 'inventory' resources were destroyed.
        - '_tf_graphql_destroyed': Indicates if 'graphql' resources were destroyed.
    """
    config._tf_inventory_hosts = {}
    config._tf_graphql_hosts = {}
    config._tf_inventory_destroyed = False
    config._tf_graphql_destroyed = False


@pytest.fixture(scope='session', autouse=True)
def e2e_inventory_resources(request, e2e_azure_tf_root, azure_env_variables, aws_env_variables, customer_account, terrafrom_remote_backend, linux_agent_token, ingestion_tag):
    """Pytest fixture to deploy and teardown the 'inventory' Terraform module for E2E testing.

    This fixture dynamically applies the 'inventory' Terraform module defined in
    'e2e_resource_inventory_tf_modules'. It uses the S3 backend configuration for state
    management and applies optional custom ingestion tags provided via the 'ingestion_tag' fixture.

    Behavior:
        - Deploys the 'inventory' Terraform module before any tests are executed.
        - Cleans up (destroys) the deployed resources after all tests are completed.

    Args:
        request: Pytest's request object to access session configuration.
        e2e_azure_tf_root(str): Path to the root directory containing Azure e2e Terraform modules.
        azure_env_variables: Fixture to set Azure credentials as environment variables.
        aws_env_variables: Fixture to set Aws credentials as environment variables for terrafrom backend.
        customer_account : Fixture providing detail of customer account like account_name
        terrafrom_remote_backend: Fixture providing terrafrom remote backend details such as s3 bucket and region.
        linux_agent_token:Fixture returns linux agent access tokens
        ingestion_tag (dict | None): Custom tags to identify the test deployment, or None.

    Yields:
        dict: A dictionary containing deployment metadata for the 'inventory' module

    Cleanup:
        - Terraform resources deployed by the 'inventory' module are destroyed after tests.

    """
    config = request.config
    hosts = {}
    start_time = time.monotonic()
    logger.info("Start deploying inventory resources")
    agent_download_url = f"https://{customer_account['account_name']}.lacework.net/mgr/v1/download/{linux_agent_token}/install.sh"
    logger.info(f"agent downalod url: {agent_download_url}")
    try:
        # Pass the tag returned by the ingestion_tag fixture, defaulting to None if not applicable
        tags = ingestion_tag  # This can be None if the fixture returns None
        os.environ['TF_VAR_AGENT_DOWNLOAD_URL'] = agent_download_url
        hosts = apply_tf_modules(
            e2e_resource_inventory_tf_modules,
            e2e_azure_tf_root,
            terrafrom_remote_backend.s3_bucket,
            terrafrom_remote_backend.s3_bucket_region,
            customer_account['account_name'],
            tags=tags
        )
        config._tf_inventory_hosts = hosts
        end_time = time.monotonic()
        duration_minutes = (end_time - start_time) / 60
        logger.debug(f"Deploying 'inventory' resources took {
                     duration_minutes:.2f} minutes.")
        yield hosts
    finally:
        logger.info("Teardown: Destroying 'inventory' resources.")
        destroy_tf_modules(hosts)
        config._tf_inventory_destroyed = True  # Mark only 'inventory' as destroyed
        if 'TF_VAR_AGENT_DOWNLOAD_URL' in os.environ:
            del os.environ['TF_VAR_AGENT_DOWNLOAD_URL']

#  placeholder for deploying graqphql resources
# @pytest.fixture(scope='session', autouse=True)
# def e2e_graphql_hosts(request, e2e_tf_root, azure_env_variables,terrafrom_remote_backend, ingestion_tag):
#     """Fixture applies all TF modules for hosts inside e2e_graphql_tf_modules."""
#     config = request.config
#     hosts = {}
#     start_time = time.monotonic()
#     tags = ingestion_tag
#     logger.info("Start deploying 'graphql' resources.")
#     try:
#         hosts = apply_tf_modules(
#             e2e_graphql_tf_modules,
#             e2e_tf_root,
#             terrafrom_remote_backend.s3_bucket,
#             terrafrom_remote_backend.s3_bucket_region,
#             tags=tags
#         )
#         config._tf_graphql_hosts = hosts
#         end_time = time.monotonic()
#         duration_minutes = (end_time - start_time) / 60
#         logger.debug(f"Deploying 'graphql' resources took {
#                      duration_minutes:.2f} minutes.")
#         yield hosts
#     finally:
#         logger.info("Teardown: Destroying 'graphql' resources.")
#         destroy_tf_modules(hosts)
#         config._tf_graphql_destroyed = True  # Mark only 'graphql' as destroyed


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    """
    Pytest hook to clean up Terraform resources at the end of the test session.

    Ensures Terraform resources for 'inventory' and 'graphql' modules are cleaned up
    if their respective fixture teardown logic fails.

    Behavior:
        - Checks individual flags (_tf_inventory_destroyed and _tf_graphql_destroyed).
        - Cleans up remaining resources accordingly.

    Args:
        session: The pytest session object.
        exitstatus: The exit status code for the pytest session.
    """
    inventory_hosts = getattr(session.config, "_tf_inventory_hosts", {})
    graphql_hosts = getattr(session.config, "_tf_graphql_hosts", {})

    if not session.config._tf_inventory_destroyed and inventory_hosts:
        logger.info(
            "Destroying remaining 'inventory' resources in pytest_sessionfinish hook.")
        destroy_tf_modules(inventory_hosts)
        session.config._tf_inventory_destroyed = True

    if not session.config._tf_graphql_destroyed and graphql_hosts:
        logger.info(
            "Destroying remaining 'graphql' resources in pytest_sessionfinish hook.")
        destroy_tf_modules(graphql_hosts)
        session.config._tf_graphql_destroyed = True

    if session.config._tf_inventory_destroyed and session.config._tf_graphql_destroyed:
        logger.info(
            "All Terraform resources have been cleaned up successfully.")
