# Repository Guidelines

This repository follows specific guidelines for maintaining code quality and test case management. Below are the instructions for setting up pre-commit hooks and the rules to follow when writing test cases.

## Code Quality Guidelines

To maintain a high standard of code quality, follow these guidelines:

### 1. Pre-commit Hook Setup

This repository uses **pre-commit** to automate code quality checks before committing changes. Follow the steps below to set up the pre-commit hooks in your local environment:

#### Install Pre-commit

To use pre-commit, first ensure it's installed on your machine. You can install it  using pip:

```bash
pip install pre-commit
```


#### Install the Pre-commit Hooks

Once `pre-commit` is installed, run the following command inside the repository folder to install the hooks and their dependencies:

```bash
pre-commit install --install-hooks
```

This command installs the hooks defined in the `.pre-commit-config.yaml` file and ensures they are run automatically on every `git commit`.

#### Run Pre-commit Hooks Manually (Optional)

You can manually run the pre-commit hooks on all files at any time by using the following command:

```bash
pre-commit run --all-files
```

This will apply the pre-commit checks across the entire codebase.



#### Automatically Running Pre-commit Hooks

After installing the hooks with the `pre-commit install --install-hooks` command, the pre-commit checks will run automatically every time you run `git commit`. This ensures that code quality checks are performed before committing to the repository.


## Test Case Guidelines

When writing test cases for this repository, please follow these rules:

### 1. API Versioning in Test Names

Test cases must indicate the API version they are using.

- Test cases for API version 1 should end with `_v1`.
- Test cases for API version 2 should end with `_v2`.

For example:
- `test_inventory_by_aws_accountId_v1`
- `test_inventory_search_ec2_instance_v2`

### 2. Docstring Format for Test Cases

All test cases must have a complete docstring that includes:

1. **Test Description**: This section should provide a short, clear explanation of the test’s purpose.
   - **Start the description immediately after the opening `"""`** with no preceding space or newline.
   - **The description must be at least 20 characters long** and provide an overview of the test case.
   - Leave one blank line between the description and the rest of the docstring.

2. **Given-When-Then format**: This ensures clarity about the context, action, and expected outcome of the test.
   - **Given**: The initial conditions or setup required for the test. (at least 5 characters)
   - **When**: The action being tested (e.g., calling an API or executing a function). (at least 20 characters)
   - **Then**: The expected result or output of the test. (at least 20 characters)
3. **Args section**: A description of all the arguments passed to the test. (at least 20 characters)

Example docstring:

```python
def test_inventory_by_aws_accountId_v2(self, api_v2_client, time_filter, account_id):
    """Verify if resources are returned for the specified AWS account using API v2.

    Given: An AWS account ID and a time filter,
    When: The inventory search API v2 is called to retrieve resources for the specified account ID with time filter,
    Then: The API should return a 200 status code, and all resources should contain the correct AWS account ID.
    Args:
        api_v2_client: API client for interacting with the Lacework inventory API v2.
        time_filter: Time filter for querying the inventory, returning start and end time in UTC.
        account_id: The AWS account ID to retrieve resources for.
    """
```
