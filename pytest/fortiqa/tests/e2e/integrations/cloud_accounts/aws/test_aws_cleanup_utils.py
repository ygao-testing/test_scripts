import pytest
from .aws_cleanup_utils import AWSCleanupHelper


@pytest.fixture
def cleanup_helper(aws_account):
    """Fixture to create an instance of AWSCleanupHelper.

    Args:
        aws_account: AWS account fixture providing credentials

    Returns:
        AWSCleanupHelper: An instance of the cleanup helper
    """
    return AWSCleanupHelper(aws_credentials=aws_account.credentials)


def test_dry_run_cleanup_s3_buckets(cleanup_helper):
    """Test listing S3 buckets for cleanup in dry run mode.

    Given:
        - An AWS account with S3 buckets
        - A cleanup helper instance
    When:
        - The cleanup_s3_buckets method is called with dry_run=True
    Then:
        - A list of bucket names should be returned
        - No buckets should be actually deleted

    Args:
        cleanup_helper: Fixture providing AWSCleanupHelper instance
    """
    buckets = cleanup_helper.cleanup_s3_buckets(dry_run=True)
    assert isinstance(buckets, list), "Should return a list of bucket names"


def test_cleanup_s3_buckets(cleanup_helper):
    """Test listing S3 buckets for cleanup.

    Given:
        - An AWS account with S3 buckets
        - A cleanup helper instance
    When:
        - The cleanup_s3_buckets method is called with dry_run=False
    Then:
        - A list of bucket names should be returned
        - All buckets should be deleted
        - The returned list should be empty

    Args:
        cleanup_helper: Fixture providing AWSCleanupHelper instance
    """
    buckets = cleanup_helper.cleanup_s3_buckets(dry_run=False)
    assert isinstance(buckets, list), "Should return a list of bucket names"
    assert len(buckets) == 0, "Should delete all buckets"


def test_dry_run_cleanup_ecs_clusters(cleanup_helper):
    """Test listing ECS clusters for cleanup in dry run mode.

    Given:
        - An AWS account with ECS clusters
        - A cleanup helper instance
    When:
        - The cleanup_ecs_clusters method is called with dry_run=True
    Then:
        - A list of cluster ARNs should be returned
        - No clusters should be actually deleted

    Args:
        cleanup_helper: Fixture providing AWSCleanupHelper instance
    """
    clusters = cleanup_helper.cleanup_ecs_clusters(dry_run=True)
    assert isinstance(clusters, list), "Should return a list of cluster ARNs"


def test_cleanup_ecs_clusters(cleanup_helper):
    """Test listing ECS clusters for cleanup.

    Given:
        - An AWS account with ECS clusters
        - A cleanup helper instance
    When:
        - The cleanup_ecs_clusters method is called with dry_run=False
    Then:
        - A list of cluster ARNs should be returned
        - All clusters should be deleted
        - The returned list should be empty

    Args:
        cleanup_helper: Fixture providing AWSCleanupHelper instance
    """
    clusters = cleanup_helper.cleanup_ecs_clusters(dry_run=False)
    assert isinstance(clusters, list), "Should return a list of cluster ARNs"
    assert len(clusters) == 0, "Should delete all clusters"


def test_dry_run_cleanup_ecs_task_definitions(cleanup_helper):
    """Test listing ECS task definitions for cleanup in dry run mode.

    Given:
        - An AWS account with ECS task definitions
        - A cleanup helper instance
    When:
        - The cleanup_ecs_task_definitions method is called with dry_run=True
    Then:
        - A list of task definition ARNs should be returned
        - No task definitions should be actually deleted

    Args:
        cleanup_helper: Fixture providing AWSCleanupHelper instance
    """
    task_defs = cleanup_helper.cleanup_ecs_task_definitions(dry_run=True)
    assert isinstance(task_defs, list), "Should return a list of task definition ARNs"


def test_cleanup_ecs_task_definitions(cleanup_helper):
    """Test listing ECS task definitions for cleanup.

    Given:
        - An AWS account with ECS task definitions
        - A cleanup helper instance
    When:
        - The cleanup_ecs_task_definitions method is called with dry_run=False
    Then:
        - A list of task definition ARNs should be returned
        - All task definitions should be deleted
        - The returned list should be empty

    Args:
        cleanup_helper: Fixture providing AWSCleanupHelper instance
    """
    task_defs = cleanup_helper.cleanup_ecs_task_definitions(dry_run=False)
    assert isinstance(task_defs, list), "Should return a list of task definition ARNs"
    assert len(task_defs) == 0, "Should delete all task definitions"


def test_dry_run_cleanup_vpcs(cleanup_helper):
    """Test listing VPCs for cleanup in dry run mode.

    Given:
        - An AWS account with VPCs
        - A cleanup helper instance
    When:
        - The cleanup_vpcs method is called with dry_run=True
    Then:
        - A list of VPC IDs should be returned
        - No VPCs should be actually deleted

    Args:
        cleanup_helper: Fixture providing AWSCleanupHelper instance
    """
    vpcs = cleanup_helper.cleanup_vpcs(dry_run=True)
    assert isinstance(vpcs, list), "Should return a list of VPC IDs"


def test_dry_run_cleanup_all(cleanup_helper):
    """Test listing all resources for cleanup in dry run mode.

    Given:
        - An AWS account with various resources (S3, ECS, VPC)
        - A cleanup helper instance
    When:
        - The cleanup_all method is called with dry_run=True
    Then:
        - A dictionary containing lists of resources should be returned
        - The dictionary should include S3 buckets, ECS clusters, task definitions, and VPCs
        - Each resource list should be properly typed
        - No resources should be actually deleted

    Args:
        cleanup_helper: Fixture providing AWSCleanupHelper instance
    """
    results = cleanup_helper.cleanup_all(dry_run=True)
    assert isinstance(results, dict), "Should return a dictionary"
    assert "s3_buckets" in results, "Should include S3 buckets"
    assert "ecs_clusters" in results, "Should include ECS clusters"
    assert "ecs_task_definitions" in results, "Should include ECS task definitions"
    assert "vpcs" in results, "Should include VPCs"

    for resource_type, resources in results.items():
        assert isinstance(resources, list), f"{resource_type} should contain a list of resources"
