import pytest
import time
import logging
import string
import os
import random
import tftest
import json
import tempfile
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from fortiqa.tests.e2e.ingestion.gcp.tf_moduels import e2e_gcp_tf_modules
from fortiqa.libs.lw.apiv1.api_client.identity.identity import IdentityV1
from fortiqa.libs.helper.date_helper import iso_to_timestamp, datetime_to_timestamp, timestamp_to_datetime
from fortiqa.tests.e2e.ingestion.gcp.identity.risk_mappings import GCP_IAM_TO_ROLE
logger = logging.getLogger(__name__)

random_id = ''.join(random.choices(string.ascii_letters, k=4)).lower()
tf_owner_prefix = f'ingestion-{random_id}'


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
    """Adds a command-line option '--not_use_ingestion_label' for pytest.

    By default, the option is False, meaning the ingestion label is used to filter GCP resources.
    When the '--not_use_ingestion_label' flag is specified, it sets the option to True,
    disabling filtering by the ingestion label.

    Args:
        parser: The pytest command-line parser object.
    """
    parser.addoption(
        "--not_use_ingestion_label",
        action="store_true",
        default=False,
        help="For ingestion-related test cases: disable filtering GCP resources by the ingestion label. "
             "By default (flag not provided), the label is used to filter resources."
    )


@pytest.fixture(scope="session")
def ingestion_label(request):
    """Fixture to generate a dynamic ingestion label used for filtering GCP resources.

    This fixture generates a unique ingestion label with the key 'test', combining:
        - The 'tf_owner_prefix' (used as the 'owner' label for GCP resource deployment).
        - A UTC timestamp in `YYYYMMDD-HHMMSS` format, ensuring compatibility with GCP labels.

    Behavior:
        - By default, the fixture generates and returns the dynamic ingestion label.
        - If the `--not_use_ingestion_label` command-line option is provided, the fixture returns `None`,
          disabling ingestion label filtering.

    Command-Line Option:
        --not_use_ingestion_label: When specified, disables the ingestion label and returns `None`.

    Returns:
        dict[str, str] | None: A dictionary containing the ingestion label.

    Example:
        {"test": "e2e-ingestion-test-abc123-20240319-063142"}

        If `--not_use_ingestion_label` is set:
        None
    """
    if request.config.getoption("not_use_ingestion_label"):
        return None
    else:
        # Format UTC timestamp in GCP-compatible format (YYYYMMDD-HHMMSS)
        utc_now = datetime.now(timezone.utc)
        formatted_timestamp = utc_now.strftime("%Y%m%d-%H%M%S")

        # Construct the ingestion label
        tag_value = f"{tf_owner_prefix}-{formatted_timestamp}"

        return {"test": tag_value}


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
    root = os.path.join(request.config.rootdir, '../terraform/e2e/gcp/')
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


@pytest.fixture(scope="session", autouse=True)
def gcp_env_variables(gcp_service_account) -> None:
    """Sets `GOOGLE_APPLICATION_CREDENTIALS` for authentication and returns the GCP project ID.

    - Creates a temporary JSON file with GCP service account credentials.
    - Sets `GOOGLE_APPLICATION_CREDENTIALS` to enable Terraform authentication for `gcloud`.
    - Yields the project ID
    """
    if 'GOOGLE_APPLICATION_CREDENTIALS' not in os.environ:
        # Convert the dataclass to a dictionary
        gcp_service_account_dict = asdict(gcp_service_account)
        # Create a temporary JSON file for GCP credentials
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_key_file:
            json.dump(gcp_service_account_dict, temp_key_file)
            temp_key_file.flush()
            os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = temp_key_file.name

    yield

    # Cleanup: Remove the environment variable and delete the temp file
    if 'GOOGLE_APPLICATION_CREDENTIALS' in os.environ:
        os.remove(os.environ['GOOGLE_APPLICATION_CREDENTIALS'])
        del os.environ['GOOGLE_APPLICATION_CREDENTIALS']


def apply_tf_modules(module_list: list[str], module_root: str, bucket_name: str, region: str, env: str, labels: dict | None = None) -> dict[str, dict]:
    """Deploys a list of Terraform modules with dynamic backend configuration and resource labeling.

    This function initializes and applies Terraform modules dynamically. A unique backend state file
    key is generated using the 'tf_owner_prefix', module name, and a timestamp. By default, the 'OWNER'
    label is applied to all GCP resources, while custom ingestion labels can optionally be provided
    for distinguishing deployments.

    Args:
        module_list (list[str]): List of Terraform module paths to be deployed.
        module_root (str): Root folder where all Terraform modules are located.
        bucket_name (str): Name of the S3 bucket used for Terraform backend state storage.
        region (str): AWS region where the S3 bucket resides.
        env (str): The environment in which the tests are run. For example, "fortiqa" or
                   "fortiqa.spork.corp".
        labels (dict | None): Optional custom labels to distinguish ingestion runs.

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
            dynamic_key = f"ingestion/{env}/gcp/test_{tf_owner_prefix}_{
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
            # Pass the labels if provided
            if labels:
                tf_vars['INGESTION_LABEL'] = labels
            logger.info(f"Initializing terraform for  {tf_module} module")
            # due to tf gcp backend issue, we may need to retry apply_tf_modules,
            # set force_copy=True to avoid interactive prompt of backend config change.
            tf.setup(init_vars=backend_config, force_copy=True)
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
        - '_tf_e2e_gcp_resources': Tracks 'e2e GCP resources' Terraform modules.
        - '_tf_e2e_gcp_resources_destroyed': Indicates if 'e2e GCP resources' resources were destroyed.
    """
    config._tf_e2e_gcp_resources = {}
    config._tf_e2e_gcp_resources_destroyed = False


@pytest.fixture(scope='session', autouse=True)
def e2e_gcp_resources(request, e2e_tf_root, gcp_env_variables, aws_env_variables, aws_account, ingestion_label, terrafrom_remote_backend, linux_agent_token, customer_account):
    """
    Pytest fixture to deploy and teardown the 'E2E GCP' Terraform module for end-to-end testing.

    This fixture dynamically applies the Terraform modules required for E2E testing on GCP,
    using the specified remote backend configuration and optional ingestion labels.

    Behavior:
        - Deploys the necessary Terraform modules before any tests are executed.
        - Sets the GCP project ID as an environment variable (`TF_VAR_PROJECT_ID`) to be
          used by Terraform.
        - Cleans up (destroys) the deployed resources after all tests are completed.

    Args:
        request: Pytest's request object to access session configuration.
        e2e_tf_root (str): Path to the root directory containing Terraform modules for GCP E2E testing.
        gcp_env_variables (str): Fixture that sets GCP credentials as environment variables
            and returns the GCP project ID.
        ingestion_label (dict | None): Custom labels to identify the test deployment, or None.
        terrafrom_remote_backend: Fixture providing Terraform remote backend details such as GCS bucket and region.
        linux_agent_token: Fixture returning Linux agent access tokens.
        customer_account (dict): Dictionary containing customer account details.

    Yields:
        dict: A dictionary containing deployment metadata for the 'E2E GCP' modules.

    Cleanup:
        - Terraform resources deployed by the 'E2E GCP' module are destroyed after tests.
        - Environment variables (`TF_VAR_AGENT_DOWNLOAD_URL` and `TF_VAR_PROJECT_ID`) are removed after execution.
    """
    config = request.config
    hosts = {}
    start_time = time.monotonic()
    labels = ingestion_label
    logger.info("Start deploying 'E2E GCP' resources.")
    agent_download_url = f"https://{customer_account['account_name']}.lacework.net/mgr/v1/download/{linux_agent_token}/install.sh"
    logger.info(f"agent downalod url: {agent_download_url}")
    try:
        os.environ['TF_VAR_AGENT_DOWNLOAD_URL'] = agent_download_url
        max_retries = 10
        retry_count = 0
        while True:
            hosts = apply_tf_modules(
                e2e_gcp_tf_modules,
                e2e_tf_root,
                aws_account.aws_terraform_s3_backend,
                aws_account.aws_terrafrom_s3_backend_region,
                customer_account['account_name'],
                labels=labels
            )
            service_account_identity_module = hosts["service_account_identity"]["tf"]
            service_account_names = service_account_identity_module.output().get("service_account_names", {})
            # workaround for an issue with terraform gcp provider, sometimes roles are not assigned.
            if len(service_account_names) == len(GCP_IAM_TO_ROLE):
                break

            logger.info(f"retrying for roles to be assigned. retry count: {retry_count}")
            time.sleep(10)
            destroy_tf_modules(hosts)
            hosts = {}
            retry_count += 1
            if retry_count > max_retries:
                raise Exception("Failed to deploy 'e2e GCP' resources after maximum retries.")

        config._tf_e2e_gcp_resources = hosts
        end_time = time.monotonic()
        duration_minutes = (end_time - start_time) / 60
        logger.debug(f"Deploying 'e2e GCP' resources took {duration_minutes:.2f} minutes.")
        yield hosts
    finally:
        logger.info("Teardown: Destroying 'e2e GCP' resources.")
        destroy_tf_modules(hosts)
        config._tf_e2e_gcp_resources_destroyed = True  # Mark only 'e2e_gcp_resources' as destroyed
        if 'TF_VAR_AGENT_DOWNLOAD_URL' in os.environ:
            del os.environ['TF_VAR_AGENT_DOWNLOAD_URL']


@pytest.fixture(scope="session")
def wait_for_identity_update_post_daily_ingestion_gcp(api_v1_client, gcp_service_account, wait_for_daily_collection_completion_gcp) -> dict[str, int]:
    """
    Pytest fixture that waits for the identity update to complete within the maximum allowed wait time (1 hour after ingestion completion).

    This fixture:
    - Uses 'startTime' from 'wait_for_daily_collection_completion_gcp', converts it to a timestamp, and uses it as 'start_time_range'.
    - Initially sets 'end_time_range' to the current UTC timestamp at the start of execution.
    - Computes the timeout as the remaining time from 'endTime' of 'wait_for_daily_collection_completion_gcp' until 1 hour after ingestion completion.
    - Calls 'check_for_identity_update' to verify the identity update within the computed timeout.
    - If the identity update is detected, updates 'end_time_range' to the current time to reflect the actual completion time.
    - Logs the time taken for the identity update.
    - Raises 'TimeoutError' if the identity update does not occur.

    Args:
        api_v1_client: Fixture providing an instance of 'ApiV1Client' for interacting with the Lacework API v1.
        wait_for_daily_collection_completion_gcp: Fixture ensuring daily ingestion collection is completed and providing the ingestion timeframe.
        gcp_service_account: Fixture providing GCP account details.

    Returns:
        dict[str, int]: Dictionary containing:
                        {
                            "start_time_range": startTime from 'wait_for_daily_collection_completion_gcp' in timestamp,
                            "end_time_range": The actual time when identity update was detected, in timestamp.
                        }
    Raises:
        TimeoutError: If the identity update does not complete within the computed timeout.

    Note:
        - 'end_time_range' is dynamically set to the current UTC timestamp at the start and updated again to reflect
          the actual completion time when the identity update is detected.
        - The computed timeout ensures the method waits up to 1 hour after execution starts.
    """
    # Get GCP project ID dynamically from the fixture
    gcp_project_id = gcp_service_account.project_id

    # Extract 'startTime' from the time_filter
    ingestion_start_time_iso = wait_for_daily_collection_completion_gcp["startTime"]
    actual_ingestion_completion_time_iso = wait_for_daily_collection_completion_gcp["endTime"]

    # Convert 'startTime' to timestamp in milliseconds
    start_time_range = iso_to_timestamp(ingestion_start_time_iso)

    # Set the current time as the initial end_time_range
    current_time = datetime.now(timezone.utc)
    end_time_range = datetime_to_timestamp(current_time)
    actual_ingestion_completion_time_dt = datetime.fromisoformat(actual_ingestion_completion_time_iso.replace("Z", "+00:00"))
    time_since_completion_seconds = (current_time - actual_ingestion_completion_time_dt).total_seconds()

    # Calculate the timeout (1 hour and 30 minutes maximum)
    # Using a fixed timeout since we don't have a completion time from a daily collection fixture
    remaining_wait_time = max(60, 5400 - time_since_completion_seconds)  # At least 60s, max 5400s

    logger.info(f"Time since daily collection completion: {time_since_completion_seconds:.2f} seconds")
    logger.info(f"Computed timeout for identity update check: {remaining_wait_time} seconds")

    # Wait for the identity update to complete
    identity_v1 = IdentityV1(api_v1_client)
    update_completed = identity_v1.check_for_identity_update(
        start_time_range, end_time_range, owner=tf_owner_prefix, cloud_provider="GCP", account_id=gcp_project_id, timeout_seconds=remaining_wait_time)

    time_since_ingestion_completion = (datetime.now(timezone.utc) - actual_ingestion_completion_time_dt).total_seconds()
    if update_completed:
        logger.info(f"GCP Identity update detected after {time_since_ingestion_completion:.2f} seconds after ingestion completion.")
        # considering the current time as end time range
        end_time_range = datetime_to_timestamp(datetime.now(timezone.utc))
        time_range = {"start_time_range": start_time_range, "end_time_range": end_time_range}
        return time_range
    else:
        raise TimeoutError(f"GCP Identity update did not complete within {time_since_ingestion_completion:.2f} seconds after ingestion completion.")


@pytest.fixture(scope="session")
def wait_for_identity_properties_update_post_daily_ingestion_gcp(api_v1_client, gcp_service_account, wait_for_identity_update_post_daily_ingestion_gcp) -> dict[str, int]:
    """
    Pytest fixture that waits for the identity properties update to complete within the maximum allowed wait time (1 hour after ingestion completion).

    This fixture:
    - Uses 'start_time_range' from 'wait_for_identity_update_post_daily_ingestion_gcp' as the start timestamp.
    - Uses 'end_time_range' from 'wait_for_identity_update_post_daily_ingestion_gcp' as the identity update time.
    - Sets 'end_time_range' to the current UTC timestamp at the start.
    - Computes the timeout as the remaining time from 'identity update time' until a max of 90 minutes.
    - Calls 'check_for_identity_PROPERTIES_update' to verify if at least one record has non-null 'PROPERTIES' within the computed timeout.
    - Logs the time taken for the identity properties update.
    - Raises 'TimeoutError' if the identity properties update does not occur.

    Args:
        api_v1_client: Fixture providing an instance of 'ApiV1Client' for interacting with the Lacework API v1.
        wait_for_identity_update_post_daily_ingestion_gcp: Fixture providing a time range for filtering.
        gcp_service_account: Fixture providing GCP account details.

    Returns:
        dict[str, int]: Dictionary containing:
                        {
                            "start_time_range": start_time_range from 'wait_for_identity_update_post_daily_ingestion_gcp',
                            "end_time_range": The actual time when identity properties update was detected, in timestamp.
                        }
    Raises:
        TimeoutError: If the identity properties update does not complete within the computed timeout.

    Note:
        - 'end_time_range' is dynamically set to the current UTC timestamp at the start and updated again to reflect
          the actual completion time when the identity properties update is detected.
        - The computed timeout ensures the method waits up to 90 minutes after the identity update completion.
    """
    # Get GCP project ID dynamically from the fixture
    gcp_project_id = gcp_service_account.project_id

    # Get start_time_range and identity update completion time
    start_time_range = wait_for_identity_update_post_daily_ingestion_gcp["start_time_range"]
    identity_update_time = wait_for_identity_update_post_daily_ingestion_gcp["end_time_range"]

    # Convert identity update time to datetime
    identity_update_time_dt = timestamp_to_datetime(identity_update_time)

    # Compute timeout (Max 30 minutes after identity update completion)
    current_time = datetime.now(timezone.utc)
    end_time_range = datetime_to_timestamp(current_time)
    time_since_identity_update = (current_time - identity_update_time_dt).total_seconds()
    remaining_wait_time = max(60, 5400 - time_since_identity_update)  # At least 60s, max 5400s (90 min)

    logger.info(f"Time since identity properties update completion: {time_since_identity_update:.2f} seconds")
    logger.info(f"Computed timeout for identity properties update check: {remaining_wait_time} seconds")

    # Wait for the identity properties update to complete
    identity_v1 = IdentityV1(api_v1_client)
    update_completed = identity_v1.check_for_identity_properties_update(
        start_time_range, end_time_range, owner=tf_owner_prefix, cloud_provider="GCP", account_id=gcp_project_id, timeout_seconds=remaining_wait_time)

    current_time = datetime.now(timezone.utc)
    time_since_identity_update = (current_time - identity_update_time_dt).total_seconds()
    if update_completed:
        logger.info(f"GCP Identity properties update detected after {time_since_identity_update:.2f} seconds after identity update completion.")
        # considering the current time as end time range
        end_time_range = datetime_to_timestamp(datetime.now(timezone.utc))
        time_range = {"start_time_range": start_time_range, "end_time_range": end_time_range}
        return time_range
    else:
        raise TimeoutError(f"GCP Identity properties update did not complete within {time_since_identity_update:.2f} seconds after identity update completion.")


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    """
    Pytest hook to clean up Terraform resources at the end of the test session.

    Ensures Terraform resources for e2e terraform modules are cleaned up
    if the respective fixture teardown logic fails.

    Behavior:
        - Checks flags(_tf_e2e_gcp_resources_destroyed ).
        - Cleans up remaining resources accordingly.

    Args:
        session: The pytest session object.
        exitstatus: The exit status code for the pytest session.
    """
    e2e_gcp_resources = getattr(session.config, "_tf_e2e_gcp_resources", {})

    if not session.config._tf_e2e_gcp_resources_destroyed and e2e_gcp_resources:
        logger.info(
            "Destroying remaining 'e2e gcp resources' in pytest_sessionfinish hook.")
        destroy_tf_modules(e2e_gcp_resources)
        session.config._tf_e2e_gcp_resources_destroyed = True

    if session.config._tf_e2e_gcp_resources_destroyed:
        logger.info(
            "All Terraform resources have been cleaned up successfully.")


@pytest.fixture(scope="session", autouse=True)
def on_board_agentless_aws_account(gcp_service_account, api_v1_client, e2e_gcp_resources):
    """Fixture to creates/deletes GCP Agentless Configuration integration"""
    yield gcp_service_account  # TODO: Implement this method
