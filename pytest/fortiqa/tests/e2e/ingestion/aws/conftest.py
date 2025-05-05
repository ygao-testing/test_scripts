import pytest
import time
import logging
import string
import os
import random
import tftest
from datetime import datetime, timedelta, timezone

from fortiqa.libs.lw.apiv1.api_client.identity.identity import IdentityV1
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard
from fortiqa.libs.lw.apiv1.api_client.cloud_accounts.integrations import Integrations
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response
from fortiqa.libs.helper.date_helper import iso_to_timestamp, datetime_to_timestamp, timestamp_to_datetime
from fortiqa.libs.aws.cloudformation import CloudformationHelper
from fortiqa.tests.e2e.ingestion.aws.tf_modules import e2e_aws_tf_modules
from fortiqa.tests.e2e.integrations.cloud_accounts.helpers import generate_and_run_aws_agentless_cft


logger = logging.getLogger(__name__)

random_id = ''.join(random.choices(string.ascii_letters, k=4)).lower()
tf_owner_prefix = f'e2e-ing-{random_id}'


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
    """Adds a command-line option '--not_use_ingestion_tag' for pytest.

    By default, the option is False, meaning the ingestion tag is used to filter AWS resources.
    When the '--not_use_ingestion_tag' flag is specified, it sets the option to True,
    disabling filtering by the ingestion tag.

    Args:
        parser: The pytest command-line parser object.
    """
    parser.addoption(
        "--not_use_ingestion_tag",
        action="store_true",
        default=False,
        help="For ingestion-related test cases: disable filtering AWS resources by the ingestion tag. "
             "By default (flag not provided), the tag is used to filter resources."
    )


@pytest.fixture(scope="session")
def ingestion_tag(request):
    """Fixture to generate a dynamic ingestion tag used for filtering AWS resources.

    This fixture generates a unique ingestion tag with the key 'Test', combining the 'tf_owner_prefix'
    (used as the 'Owner' tag for AWS resource deployment) and a UTC timestamp in ISO 8601 format
    with milliseconds and 'Z' appended. The tag helps identify and filter AWS resources deployed
    during tests.

    Behavior:
        - By default, the fixture generates and returns the dynamic ingestion tag.
        - If the '--not_use_ingestion_tag' command-line option is provided, the fixture returns None,
          disabling ingestion tag filtering.

    Key Components:
        - 'tf_owner_prefix': Used as the Owner tag for AWS resources.
        - ISO 8601 UTC timestamp: Ensures each tag is unique across test runs.

    Command-Line Option:
        --not_use_ingestion_tag: When specified, disables the ingestion tag and returns None.

    Returns:
        dict[str, str] | None: A dictionary containing the ingestion tag.
            Example:
                {"Test": "e2e-ingestion-test-abc123-2024-12-16T07:29:06.263Z"}

            If '--not_use_ingestion_tag' is set:
                None
    """
    if request.config.getoption("not_use_ingestion_tag"):
        return None
    else:
        # Format the UTC timestamp in ISO 8601 format with milliseconds and 'Z'
        utc_now = datetime.now(timezone.utc)

        # Format the UTC timestamp in ISO 8601 format with milliseconds and 'Z'
        formatted_timestamp = utc_now.strftime(
            "%Y-%m-%dT%H:%M:%S") + f".{utc_now.microsecond // 1000:03d}Z"
        return {"Test": f'{tf_owner_prefix}-{formatted_timestamp}'}


@pytest.fixture(scope='session')
def aws_region(request):
    """Pytest fixture to return an AWS region. Uses 'request.param' if available,
    otherwise defaults to 'us-east-2'.

    Returns:
        str: The AWS region.
    """
    return getattr(request, 'param', 'us-east-2')


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
def e2e_tf_root(request) -> str:
    """Fixture returns root folder for e2e test lacework provider TF modules."""
    root = os.path.join(request.config.rootdir, '../terraform/e2e/aws/')
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
def wait_for_explorer_latest_update_time_to_be_updated_post_daily_ingestion_aws(api_v1_client, wait_for_daily_collection_completion_aws) -> dict[str, str] | None:
    """Pytest fixture that waits for the Explorer's latest update time to be updated post daily ingestion completion for AWS.
    Note:
            This fixture includes an additional 60-minute wait after the daily collection completion for AWS.
            This wait is necessary due to a known issue (https://lacework.atlassian.net/issues/PSP-3030),
            where the Explorer's latest update time might be prematurely updated by daily collections from
            other cloud providers (e.g., Azure) that complete sooner than AWS.
            This premature update causes AWS-specific Explorer test cases to fail, as the Explorer job for AWS is not yet completed.
            The 30-minute delay ensures that the Explorer's latest update time reflects AWS ingestion updates accurately.
            This delay will be removed once the Explorer latest update functionality is enhanced to provide provider-specific update times for AWS.


    This fixture uses the 'api_v1_client' and the 'wait_for_daily_collection_completion_aws' fixture to monitor the Explorer's
    latest update timestamps ('LATEST_START_TIME' and 'LATEST_END_TIME'). It begins monitoring from the ingestion completion
    end time ('endTime') provided by the 'wait_for_daily_collection_completion_aws' fixture. It periodically queries the Explorer
    API to ensure that the timestamps fall within the specified ingestion timeframe. If the update occurs within 90 minutes,
    it returns a dictionary containing the start and end timestamps in ISO 8601 format, along with the actual timestamp when the
    update was detected.

    If the specified monitoring timeframe (90 minutes) has already elapsed when the fixture starts, it raises a 'TimeoutError'.
    Similarly, if the timestamps are not updated within 90 minutes of monitoring, it also raises a 'TimeoutError'.

    Args:
        api_v1_client: Fixture providing an instance of 'ApiV1Client' for interacting with the Lacework API v1.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing
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
    time_filter = wait_for_daily_collection_completion_aws
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
    # from line 216 to 221 is related to the note
    time_elapsed_since_collection_completion = (datetime.now(timezone.utc) - start_time)
    while time_elapsed_since_collection_completion < timedelta(minutes=60):
        logger.info(f"{time_elapsed_since_collection_completion.total_seconds() / 60} minutes passed since AWS collection completion")
        logger.info("Sleeping for 60 seconds as 60 minutes have not passed since AWS collection completion.")
        time.sleep(60)
        time_elapsed_since_collection_completion = (datetime.now(timezone.utc) - start_time)
    # start of checking the explorer latest update
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
        is_within_range = daily_collection_start_time_str < last_update_str
        if not is_within_range:
            logger.info(
                "Sleeping for 60 seconds before retrying to get Explorer's latest update end time.")
            time.sleep(60)

    time_diff = datetime.now(timezone.utc) - datetime.fromisoformat(
        daily_collection_actual_completion_end_time_str.replace("Z", "+00:00"))
    if is_within_range:
        logger.debug(f"Explorer latest update time get updated {
                     time_diff.total_seconds()} seconds post collection completion")

        latest_update_period = {
            "startTime": latest_start_time_str,
            "endTime": last_update_str,
            "actual_explorer_update": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        }
        logger.debug(f"Latest update time period: {latest_update_period}")
        return latest_update_period

    else:
        raise TimeoutError(f"Explorer latest update did not get updated in {
                           max_wait} minutes after ingestion completion.")


@pytest.fixture(scope="session")
def wait_for_identity_update_post_daily_ingestion_aws(api_v1_client, aws_account, wait_for_daily_collection_completion_aws) -> dict[str, int]:
    """
    Pytest fixture that waits for the identity update to complete within the maximum allowed wait time (1 hour after ingestion completion).

    This fixture:
    - Uses 'startTime' from 'wait_for_daily_collection_completion_aws', converts it to a timestamp, and uses it as 'start_time_range'.
    - Initially sets 'end_time_range' to the current UTC timestamp at the start of execution.
    - Computes the timeout as the remaining time from 'endTime' of 'wait_for_daily_collection_completion_aws' until 1 hour after ingestion completion.
    - Calls 'check_for_identity_update' to verify the identity update within the computed timeout.
    - If the identity update is detected, updates 'end_time_range' to the current time to reflect the actual completion time.
    - Logs the time taken for the identity update.
    - Raises 'TimeoutError' if the identity update does not occur.

    Args:
        api_v1_client: Fixture providing an instance of 'ApiV1Client' for interacting with the Lacework API v1.
        wait_for_daily_collection_completion_aws: Fixture ensuring daily ingestion collection is completed and providing the ingestion timeframe.
        aws_account: Fixture providing AWS account details.

    Returns:
        dict[str, int]: Dictionary containing:
                        {
                            "start_time_range":  startTime from 'wait_for_daily_collection_completion_aws' in timestamp,
                            "end_time_range": The actual time when identity update was detected, in timestamp.
                        }
    Raises:
        TimeoutError: If the identity update does not complete within the computed timeout.

    Note:
        - 'end_time_range' is dynamically set to the current UTC timestamp at the start and updated again to reflect
          the actual completion time when the identity update is detected.
        - The computed timeout ensures the method waits up to 1 hour after ingestion completion.
    """
    # Get AWS account ID dynamically from the fixture
    aws_account_id = aws_account.aws_account_id
    # Extract 'startTime' and 'endTime' (actual scan completion) from the daily collection fixture
    ingestion_start_time_iso = wait_for_daily_collection_completion_aws["startTime"]
    actual_ingestion_completion_time_iso = wait_for_daily_collection_completion_aws["endTime"]
    # Convert 'startTime' to timestamp in milliseconds
    start_time_range = iso_to_timestamp(ingestion_start_time_iso)
    # Compute 'end_time_range' by adding 1 hour (3600 seconds)
    # end_time_range = start_time_range + (3600 * 1000)  # Convert to milliseconds
    # Calculate how much time has passed since daily collection completion
    current_time = datetime.now(timezone.utc)
    end_time_range = datetime_to_timestamp(current_time)
    actual_ingestion_completion_time_dt = datetime.fromisoformat(actual_ingestion_completion_time_iso.replace("Z", "+00:00"))
    time_since_completion_seconds = (current_time - actual_ingestion_completion_time_dt).total_seconds()

    # Calculate the remaining wait time (Max 1 hour and 30 minutes after ingestion completion)
    remaining_wait_time = max(60, 5400 - time_since_completion_seconds)  # At least 60s, max 5400s

    logger.info(f"Time since daily collection completion: {time_since_completion_seconds:.2f} seconds")
    logger.info(f"Computed timeout for identity update check: {remaining_wait_time} seconds")

    # Wait for the identity update to complete
    identity_v1 = IdentityV1(api_v1_client)
    update_completed = identity_v1.check_for_identity_update(
        start_time_range, end_time_range, owner=tf_owner_prefix, cloud_provider="AWS", account_id=aws_account_id, timeout_seconds=remaining_wait_time)

    time_since_ingestion_completion = (datetime.now(timezone.utc) - actual_ingestion_completion_time_dt).total_seconds()
    if update_completed:
        logger.info(f"Identity update detected {time_since_ingestion_completion:.2f} seconds after ingestion completion.")
        # considering the current time as end time range
        end_time_range = datetime_to_timestamp(datetime.now(timezone.utc))
        time_range = {"start_time_range": start_time_range, "end_time_range": end_time_range}
        return time_range

    else:
        raise TimeoutError(f"Identity update did not complete within {time_since_ingestion_completion:.2f} seconds after ingestion completion.")


@pytest.fixture(scope="session")
def wait_for_identity_properties_update_post_identity_update_aws(
    api_v1_client, aws_account, wait_for_identity_update_post_daily_ingestion_aws
) -> dict[str, int]:
    """
    Pytest fixture that waits for identity properties update to complete after the identity ingestion update.

    This fixture:
    - Uses 'start_time_range' from 'wait_for_identity_update_post_daily_ingestion_aws' as the start timestamp.
    - Uses 'end_time_range' from 'wait_for_identity_update_post_daily_ingestion_aws' as the identity update time.
    - Sets 'end_time_range' to the current UTC timestamp at the start.
    - Computes the timeout as the remaining time from 'identity update time' until a max of 90 minutes.
    - Calls 'check_for_identity_PROPERTIES_update' to verify if at least one record has non-null 'PROPERTIES' within the computed timeout.
    - Logs the time taken for the properties update.
    - Raises 'TimeoutError' if the properties update does not occur.

    Args:
        api_v1_client: Fixture providing an instance of 'ApiV1Client' for interacting with the Lacework API v1.
        wait_for_identity_update_post_daily_ingestion_aws: Fixture ensuring identity updates post daily ingestion collection completion and providing a  time filter.

    Returns:
        dict[str, int]: Dictionary containing:
                        {
                            "start_time_range": 'start_time_range' from 'wait_for_identity_update_post_daily_ingestion_aws',
                            "end_time_range": The actual time when properties update was detected, in timestamp.
                        }

    Raises:
        TimeoutError: If the identity properties update does not complete within the computed timeout.

    Note:
        - 'end_time_range' is dynamically set to the current UTC timestamp at the start and updated again to reflect
          the actual completion time when the properties update is detected.
        - The computed timeout ensures the method waits up to 90 minutes after the identity update completion.
    """
    aws_account_id = aws_account.aws_account_id

    # Get start_time_range and identity update completion time
    start_time_range = wait_for_identity_update_post_daily_ingestion_aws["start_time_range"]
    identity_update_time = wait_for_identity_update_post_daily_ingestion_aws["end_time_range"]

    # Convert identity update time to datetime
    identity_update_time_dt = timestamp_to_datetime(identity_update_time)

    # Compute timeout (Max 30 minutes after identity update completion)
    current_time = datetime.now(timezone.utc)
    end_time_range = datetime_to_timestamp(current_time)
    time_since_identity_update = (current_time - identity_update_time_dt).total_seconds()
    remaining_wait_time = max(60, 5400 - time_since_identity_update)  # At least 60s, max 5400s (90 min)

    logger.info(f"Time since identity update completion: {time_since_identity_update:.2f} seconds")
    logger.info(f"Computed timeout for identity properties update check: {remaining_wait_time} seconds")

    identity_v1 = IdentityV1(api_v1_client)
    update_completed = identity_v1.check_for_identity_properties_update(
        start_time_range=start_time_range,
        end_time_range=end_time_range,
        owner=tf_owner_prefix,
        cloud_provider="AWS",
        account_id=aws_account_id,
        timeout_seconds=remaining_wait_time
    )
    current_time = datetime.now(timezone.utc)
    time_since_identity_update = (current_time - identity_update_time_dt).total_seconds()

    if update_completed:
        logger.info(f"Identity properties update detected {time_since_identity_update:.2f} seconds after identity update completion.")
        end_time_range = datetime_to_timestamp(datetime.now(timezone.utc))
        logger.info(f"Identity properties update completion time: {end_time_range}")
        return {"start_time_range": start_time_range, "end_time_range": end_time_range}

    else:
        raise TimeoutError(f"Identity properties update did not complete within {time_since_identity_update:.2f} seconds after identity update completion.")


def apply_tf_modules(module_list: list[str], module_root: str, bucket_name: str, region: str, env: str, tags: dict | None = None) -> dict[str, dict]:
    """Deploys a list of Terraform modules with dynamic backend configuration and resource tagging.

    This function initializes and applies Terraform modules dynamically. A unique backend state file
    key is generated using the 'tf_owner_prefix', module name, and a timestamp. By default, the 'OWNER'
    tag is applied to all AWS resources, while custom ingestion tags can optionally be provided
    for distinguishing deployments.

    Args:
        module_list (list[str]): List of Terraform module paths to be deployed.
        module_root (str): Root folder where all Terraform modules are located.
        bucket_name (str): Name of the S3 bucket used for Terraform backend state storage.
        region (str): AWS region where the S3 bucket resides.
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
            dynamic_key = f"ingestion/{env}/aws/test_{tf_owner_prefix}_{
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
        - '_tf_e2e_aws_resources': Tracks 'e2e aws resources' Terraform modules.
        - '_tf_e2e_aws_resources_destroyed': Indicates if 'e2e aws resources' resources were destroyed.
    """
    config._tf_e2e_aws_resources = {}
    config._tf_e2e_aws_resources_destroyed = False


@pytest.fixture(scope='session', autouse=True)
def e2e_aws_resources(request, e2e_tf_root, aws_env_variables, aws_account, ingestion_tag, linux_agent_token, customer_account):
    """Fixture applies all TF modules for e2e aws inside e2e_aws_tf_modules."""
    config = request.config
    hosts = {}
    start_time = time.monotonic()
    tags = ingestion_tag
    logger.info("Start deploying 'E2E Aws' resources.")
    agent_download_url = f"https://{customer_account['account_name']}.lacework.net/mgr/v1/download/{linux_agent_token}/install.sh"
    logger.info(f"agent downalod url: {agent_download_url}")
    try:
        os.environ['TF_VAR_AGENT_DOWNLOAD_URL'] = agent_download_url
        hosts = apply_tf_modules(
            e2e_aws_tf_modules,
            e2e_tf_root,
            aws_account.aws_terraform_s3_backend,
            aws_account.aws_terrafrom_s3_backend_region,
            customer_account['account_name'],
            tags=tags
        )
        config._tf_e2e_aws_resources = hosts
        end_time = time.monotonic()
        duration_minutes = (end_time - start_time) / 60
        logger.debug(f"Deploying 'e2e aws' resources took {
                     duration_minutes:.2f} minutes.")
        yield hosts
    finally:
        logger.info("Teardown: Destroying 'e2e awa' resources.")
        destroy_tf_modules(hosts)
        config._tf_e2e_aws_resources_destroyed = True  # Mark only 'e2e_aws_resources' as destroyed
        if 'TF_VAR_AGENT_DOWNLOAD_URL' in os.environ:
            del os.environ['TF_VAR_AGENT_DOWNLOAD_URL']


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    """
    Pytest hook to clean up Terraform resources at the end of the test session.

    Ensures Terraform resources for e2e terraform modules are cleaned up
    if the respective fixture teardown logic fails.

    Behavior:
        - Checks flags(_tf_e2e_aws_resources_destroyed ).
        - Cleans up remaining resources accordingly.

    Args:
        session: The pytest session object.
        exitstatus: The exit status code for the pytest session.
    """
    e2e_aws_resources = getattr(session.config, "_tf_e2e_aws_resources", {})

    if not session.config._tf_e2e_aws_resources_destroyed and e2e_aws_resources:
        logger.info(
            "Destroying remaining 'e2e aws' resources in pytest_sessionfinish hook.")
        destroy_tf_modules(e2e_aws_resources)
        session.config._tf_e2e_aws_resources_destroyed = True

    if session.config._tf_e2e_aws_resources_destroyed:
        logger.info(
            "All Terraform resources have been cleaned up successfully.")


@pytest.fixture(scope="session", autouse=True)
def on_board_agentless_aws_account(aws_account, api_v1_client, e2e_aws_resources):
    """Fixture to creates/deletes AWS Agentless Configuration integration"""
    cft_helper = CloudformationHelper(aws_credentials=aws_account.credentials)
    logger.info("on_board_agentless_aws_account()")
    account_id = aws_account.aws_account_id
    account_type = "AWS_SIDEKICK"
    payload = {
        "TYPE": account_type,
        "ENABLED": 1,
        "IS_ORG": 0,
        "NAME": f"{tf_owner_prefix}_test",
        "DATA": {
            "AWS_ACCOUNT_ID": account_id,
            "SCAN_FREQUENCY": 6,
            "SCAN_HOST_VULNERABILITIES": True,
            "SCAN_CONTAINERS": True,
            "SCAN_STOPPED_INSTANCES": True,
            "SCAN_MULTI_VOLUME": True,
            "SCAN_SHORT_LIVED_INSTANCES": False
        },
        "ENV_GUID": ""
    }
    response = Integrations(api_v1_client).add_agentless_cloud_account(payload=payload)
    assert response.status_code == 201, f"Failed to add agentless aws account, err: {response.text}"
    intg_guid = response.json()['data'][0]["INTG_GUID"]
    stack_id = generate_and_run_aws_agentless_cft(api_v1_client=api_v1_client, intg_guid=intg_guid, aws_credentials=aws_account.credentials)
    yield aws_account
    cft_helper.delete_stack_and_wait(stack_id)
    response = Integrations(api_v1_client).delete_agentless_cloud_account(intg_guid)
    assert response.status_code == 200, f"Failed to delete agentless aws account, err: {response.text}"
