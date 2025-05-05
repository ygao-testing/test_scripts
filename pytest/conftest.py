import os
import sys
import pytest
import logging

from fortiqa.tests import settings

logging.getLogger("faker").setLevel(logging.ERROR)
repo_root_dir = os.path.dirname(os.path.dirname(__file__))
sys.path.append(repo_root_dir)
pytest_plugins = [
    "fortiqa.tests.fixtures",
    "fortiqa.tests.ui.fixtures",
    "fortiqa.tests.e2e.agents.fixtures",
    "fortiqa.tests.e2e.ingestion.aws.resource_inventory.rds.fixtures",
    "fortiqa.tests.e2e.ingestion.aws.resource_inventory.s3.fixtures",
    "fortiqa.tests.e2e.ingestion.aws.resource_inventory.iam.fixtures",
    "fortiqa.tests.e2e.ingestion.azure.resource_inventory.vm.fixtures",
    "fortiqa.tests.e2e.ingestion.azure.resource_inventory.identity.fixtures",
]


def pytest_addoption(parser):
    """
    Add custom command line options for pytest.

    This function adds a new command line option --run_cloud_integrations,
    which when provided allows cloud integration tests to be run. Otherwise,
    these tests will be skipped by default.

    Args:
        parser: The parser object used to add options.
    """
    parser.addoption(
        "--run_cloud_integrations", action="store_true", default=False, help="run cloud account integration tests"
    )
    parser.addoption("--reuse_aws_account", action="store_true", help="To use existing AWS account")
    parser.addoption("--run-slow-self-deployment-tests", action="store_true", help="run slow integration tests")


def pytest_collection_modifyitems(config, items):
    """
    Mark cloud integration tests with the skip marker if --run_cloud_integrations is not set.

    This function checks if the --run_cloud_integrations option is provided when
    running tests. If the option is not provided, it adds a skip marker to any
    tests that are marked with 'cloud_integrations', preventing them from being run.

    Args:
        config: The pytest configuration object, which holds the command-line options.
        items: The list of all collected test items.
    """
    if config.getoption("--run_cloud_integrations"):
        return
    skip_cloud_integrations = pytest.mark.skip(reason="need --run_cloud_integrations option to run")
    for item in items:
        if "cloud_integrations" in item.keywords:
            item.add_marker(skip_cloud_integrations)

    if config.getoption("--run-slow-self-deployment-tests"):
        return
    skip_slow_self_deployment_test = pytest.mark.skip(reason="quick run positive cases and skip slow self deployment tests")
    for item in items:
        if "slow_self_deployment_test" in item.keywords:
            item.add_marker(skip_slow_self_deployment_test)


def pytest_ignore_collect(path, config):
    """Skip collecting the entire 'explorer' module if a condition is met."""
    if "/new_explorer/" in str(path) or "/test_new_graphql/" in str(path):
        if should_skip_new_explorer():
            return True
    return False


def should_skip_new_explorer():
    """Define the condition to skip the New E2E Explorer Test."""
    return 'sgmtest' not in settings.app.customer['account_name']
