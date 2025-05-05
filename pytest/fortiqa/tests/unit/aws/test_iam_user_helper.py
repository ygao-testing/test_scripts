import logging
import pytest
from fortiqa.libs.aws.iam_user import IAMUserHelper
from fortiqa.libs.aws.data_class.iam_data_classes import IAMUser

logger = logging.getLogger(__name__)


@pytest.fixture(scope='function')
def iam_user_helper(aws_account) -> IAMUserHelper:
    """Fixture to provide an instance of IAMUserHelper for IAM User operations.

    Returns:
        IAMUserHelper: An instance of IAMUserHelper initialized with default settings.
    """
    return IAMUserHelper(aws_credentials=aws_account.credentials)


class TestIAMUserHelper:
    """Test class for IAMUserHelper functionality."""

    def test_create_and_delete_iam_user(self, iam_user_helper: IAMUserHelper):
        """Test creating and deleting an IAM user with access keys.
        Given:
            iam_user_helper (IAMUserHelper): An instance of IAMUserHelper to perform the tests.
        When:
            Creating and deleting an IAM user with access keys.
        Then:
            Verify that the user is created, deleted, and not deleted twice.

        Args:
            iam_user_helper (IAMUserHelper): An instance of IAMUserHelper to perform the tests.
        """
        # Test data
        test_user_name = "test-user-temp"
        test_tags = {"Environment": "test_ecr_onboarding", "Project": "fortiqa"}

        try:
            # Create user and verify
            user: IAMUser = iam_user_helper.create_iam_user(
                user_name=test_user_name,
                tags=test_tags
            )

            assert user.user_name == test_user_name
            assert user.tags == test_tags
            assert user.access_key_id is not None
            assert user.secret_access_key is not None
            logger.info(f"Successfully created IAM user: {test_user_name}")
            # Delete user and verify
            delete_success = iam_user_helper.delete_iam_user(test_user_name)
            assert delete_success
            logger.info(f"Successfully deleted IAM user: {test_user_name}")

            # Verify user is deleted by attempting to delete again
            delete_result = iam_user_helper.delete_iam_user(test_user_name)
            assert not delete_result  # Should return False as user no longer exists

        except Exception as e:
            logger.error(f"Test failed with error: {str(e)}")
            # Cleanup in case of test failure
            iam_user_helper.delete_iam_user(test_user_name)
            raise
