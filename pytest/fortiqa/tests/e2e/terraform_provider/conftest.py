import os

import pytest
import tftest

from fortiqa.tests import settings


@pytest.fixture
def lacework_provider_root(request) -> str:
    """Fixture returns root folder for lacework provider TF modules."""
    root = os.path.join(request.config.rootdir, '../terraform/lacework_provider/')
    print(f'{root=}')
    return root


@pytest.fixture
def aws_env_variables(aws_account) -> None:
    """Fixture sets and deletes AWS credentials as env variables."""
    os.environ['AWS_ACCESS_KEY_ID'] = aws_account.aws_access_key_id
    os.environ['AWS_SECRET_ACCESS_KEY'] = aws_account.aws_secret_access_key
    yield
    del os.environ['AWS_ACCESS_KEY_ID']
    del os.environ['AWS_SECRET_ACCESS_KEY']


@pytest.fixture
def lacework_env_variables() -> None:
    """Fixture sets and deletes LW credentials as env variables."""
    customer = settings.app.customer
    os.environ['LW_ACCOUNT'] = customer['account_name']
    os.environ['LW_API_KEY'] = customer['lw_api_key']
    os.environ['LW_API_SECRET'] = customer['lw_secret']
    yield
    del os.environ['LW_ACCOUNT']
    del os.environ['LW_API_KEY']
    del os.environ['LW_API_SECRET']


@pytest.fixture
def deploy_lacework_tf_module(request, lacework_provider_root, lacework_env_variables) -> list:
    """Fixture deploys/destroys given TF module"""
    tf = tftest.TerraformTest(request.param, lacework_provider_root)
    tf.setup()
    tf.apply()
    yield tf
    tf.destroy()


@pytest.fixture
def load_lacework_tf_module(request, lacework_provider_root, lacework_env_variables) -> list:
    """Fixture loads given TF module without applying"""
    tf = tftest.TerraformTest(request.param, lacework_provider_root)
    tf.setup()
    yield tf
    tf.destroy()


@pytest.fixture
def lw_api_create_delete_resource(request, api_v2_client):
    """Fixture creates and deletes resources using Lacework API.

    This fixture is parameterized and uses the provided `api_client_type` and `payload`
    to create a resource via the Lacework API. It ensures that the resource is created
    before the test runs and deleted after the test completes using API.

    Parameters:
        request: A request object that provides access to the parameters
                            of the fixture.
        api_v2_client: An instance of the API client to interact with the Lacework API.

    Yields:
        wrapped_client (object): An instance of the API client wrapped with the specific
                                resource.

    Raises:
        AssertionError: If the resource creation fails (status code is not 201) or
                        if the resource deletion fails (status code is not 204).
    """
    api_type = request.param["api_client_type"]
    payload = request.param["payload"]
    wrapped_client = api_type(api_v2_client, payload)
    resp = wrapped_client.create_resource()
    assert resp.status_code == 201, f'Failed to create new resource {resp.text}'
    yield wrapped_client
    resp = wrapped_client.delete_resource(resource_name=payload.get("name", ""))


@pytest.fixture
def lw_apiv1_resource(request, api_v1_client):
    """Fixture creates and deletes resources using Lacework API V1."""
    api_type = request.param["api_client_type"]
    payload = request.param["payload"]
    wrapped_client = api_type(api_v1_client, payload)
    resp = wrapped_client.create_resource()
    assert resp.status_code == 201, f'Failed to create new resource {resp.text}'
    yield wrapped_client
    resp = wrapped_client.delete_resource(resource_name=payload.get("name", ""))
