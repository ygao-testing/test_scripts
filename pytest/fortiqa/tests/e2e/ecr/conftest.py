import pytest
import logging
import string
import os
import random

from pathlib import PurePath
from fortiqa.tests.e2e.ecr.docker_files import docker_file_dict
from fortiqa.libs.helper.docker_helper import DockerHelper
from fortiqa.libs.aws.ecr_helper import ECRHelper
from fortiqa.libs.lw.apiv1.api_client.container_registries.integrations import Integrations

logger = logging.getLogger(__name__)

dockerfile_folder_path = "fortiqa/libs/data/dockerfiles/"


@pytest.fixture(scope="package")
def random_id():
    """Generate prefix for resources"""
    random_id = ''.join(random.choices(string.ascii_letters, k=4)).lower()
    return f'ecr-test-{random_id}'


@pytest.fixture(scope="package", params=['us-east-1'])
def ecr_deploy_region(request):
    """Specify the region to deploy the ECR"""
    if request.param:
        return request.param


@pytest.fixture(scope='package')
def aws_env_variables(aws_account) -> None:
    """Fixture sets and deletes AWS credentials as env variables."""
    os.environ['AWS_ACCESS_KEY_ID'] = aws_account.aws_access_key_id
    os.environ['AWS_SECRET_ACCESS_KEY'] = aws_account.aws_secret_access_key
    yield
    del os.environ['AWS_ACCESS_KEY_ID']
    del os.environ['AWS_SECRET_ACCESS_KEY']


@pytest.fixture(scope="package")
def dockerfile_path():
    """
    Fixture to get DockerFile Path

    docker_file_name will only be a docker file name, not the full path
    """
    repo_root_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    project_folder = PurePath(repo_root_dir)
    repo_root = project_folder.parents[1]

    def _dockerfile_path(docker_file_name: str) -> str:
        docker_file_path = os.path.join(repo_root, f"{dockerfile_folder_path}{docker_file_name}")
        logger.info(f"{docker_file_path=}")
        return docker_file_path
    return _dockerfile_path


@pytest.fixture(scope="package")
def build_test_image(request, random_id, aws_env_variables):
    """Build Docker Image using dockerfile path"""
    docker_helper = DockerHelper()
    built_image = []

    def remove_docker_images():
        logger.info("Remove created docker images")
        for docker_image in built_image:
            docker_helper.remove_image(docker_image)

    request.addfinalizer(remove_docker_images)

    def _build_test_image(docker_image_name: str, docker_file_path: str):
        docker_image_name = f"{random_id}-{docker_image_name}"
        logger.info(f"Build docker image {docker_image_name} from dockerfile {docker_file_path}")
        docker_helper.build_image(dockerfile_path=docker_file_path, image_name=docker_image_name)
        built_image.append(docker_image_name)
        return docker_image_name

    return _build_test_image


@pytest.fixture(scope="package")
def push_docker_image_to_ecr(request, ecr_deploy_region, aws_env_variables):
    """Fixture to ensure the docker image is pushed to the ECR"""
    ecr_helper = ECRHelper(region=ecr_deploy_region)
    docker_helper = DockerHelper()

    def cleanup_local_tagged_images():
        for tagged_image in created_images_by_tagging:
            docker_helper.remove_image(tagged_image)

    request.addfinalizer(cleanup_local_tagged_images)

    created_images_by_tagging = []

    def _push_docker_image_to_ecr(docker_image: str, repository_name: str):
        """
        Function to push image to ECR repository
        :param docker_image: Name of the docker image tag
        :param repository_name: Name of the repo inside AWS ECR
        """
        local_tagged_image = ecr_helper.push_image_to_ecr(image_name=docker_image, repository_name=repository_name)
        created_images_by_tagging.append(local_tagged_image)

    return _push_docker_image_to_ecr


@pytest.fixture(scope="package")
def build_images_and_push_to_ecr(request, build_test_image, random_id, ecr_deploy_region, push_docker_image_to_ecr, dockerfile_path, aws_env_variables):
    """Fixture to build all images, and push to ECR"""
    ecr_helper = ECRHelper(region=ecr_deploy_region)

    def cleanup_ecr():
        for repo_name in created_repo:
            ecr_helper.cleanup_ecr(repo_name)
            ecr_helper.delete_repository(repository_name=repo_name)

    request.addfinalizer(cleanup_ecr)

    created_repo = []
    for os_version in docker_file_dict:
        repo_name = f"{random_id}-{os_version}"
        ecr_helper.create_repository(repository_name=repo_name)
        created_repo.append(repo_name)
        for image_version in docker_file_dict[os_version]:
            docker_file_path = dockerfile_path(image_version)
            docker_image = build_test_image(docker_image_name=image_version, docker_file_path=docker_file_path)
            push_docker_image_to_ecr(docker_image, repo_name)


@pytest.fixture(scope="package")
def image_registry_domain(aws_account, ecr_deploy_region):
    """Return the Image registry domain according to the ECR build region and AWS account ID"""
    account_id = aws_account.aws_account_id
    image_registry_domain = f"{account_id}.dkr.ecr.{ecr_deploy_region}.amazonaws.com"
    return image_registry_domain


@pytest.fixture(scope="package")
def onboard_container_registry(aws_account, api_v1_client, random_id, ecr_deploy_region, build_images_and_push_to_ecr, image_registry_domain):
    """Fixture to creates/deletes AWS Agentless Configuration integration"""
    logger.info("onboard_container_registry()")
    aws_access_key, aws_secret = aws_account.aws_access_key_id, aws_account.aws_secret_access_key
    payload = {
        "TYPE": "CONT_VULN_CFG",
        "ENABLED": 1,
        "IS_ORG": 0,
        "NAME": f"{random_id}-registry",
        "DATA": {
            "ACCESS_KEY_CREDENTIALS": {
                "ACCESS_KEY_ID": aws_access_key,
                "SECRET_ACCESS_KEY": aws_secret
            },
            "AWS_AUTH_TYPE": "AWS_ACCESS_KEY",
            "REGISTRY_TYPE": "AWS_ECR",
            "REGISTRY_DOMAIN": image_registry_domain,
            "LIMIT_BY_TAG": [],
            "LIMIT_BY_LABEL": [],
            "LIMIT_BY_REP": [],
            "LIMIT_NUM_IMG": 15,
            "NON_OS_PACKAGE_EVAL": True
        },
        "PROPS": {
            "tags": "AWS_ECR"
        },
        "ENV_GUID": ""
    }
    response = Integrations(api_v1_client).add_container_registry(payload=payload)
    assert response.status_code == 201, f"Failed to add container registry, err: {response.text}"
    intg_guid = response.json()['data'][0]["INTG_GUID"]
    yield intg_guid
    response = Integrations(api_v1_client).delete_container_registry(intg_guid)
    assert response.status_code == 200, f"Failed to delete container registry, err: {response.text}"
