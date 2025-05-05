import logging

from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.container_vulnerabilities_helper import ContainerVulnerabilitiesHelper
from fortiqa.libs.lw.apiv1.helpers.vulnerabilities.new_vulnerability_dashboard_helper import NewVulnerabilityDashboardHelper
from fortiqa.libs.lw.apiv1.api_client.container_registries.integrations import Integrations
from fortiqa.libs.aws.ecr_helper import ECRHelper
from fortiqa.tests.e2e.ecr.docker_files import docker_file_dict

logger = logging.getLogger(__name__)


def test_image_found_in_vuln(api_v1_client, build_images_and_push_to_ecr, random_id,
                             onboard_container_registry, image_registry_domain):
    """Verify that images pushed to the ECR are scanned by Lacework, and returned by API.

    Given: AWS ECR deployed, local docker images built and pushed to the ECR, and Container Registry is added to Lacework
    When: Listing Vulnerability under Image Registry
    Then: Images added to the ECR should be listed

    Args:
        api_v1_client: API V1 client for interacting with the Lacework.
        random_id: Prefix of created resource names
        build_images_and_push_to_ecr: Built images that were pushed to ECR
        onboard_container_registry: Onboarded Container Registry INTG_GUID
        image_registry_domain: ECR domain including deployed region name
    """
    Integrations(api_v1_client).wait_until_container_registry_success(intg_guid=onboard_container_registry, timeout=6000)
    container_vuln_helper = ContainerVulnerabilitiesHelper(user_api=api_v1_client)
    new_vuln_helper = NewVulnerabilityDashboardHelper(user_api=api_v1_client)
    error_message = []
    for os_version in docker_file_dict:
        repo_name = f"{random_id}-{os_version}"
        for image_version in docker_file_dict[os_version]:
            image_tag = f"{random_id}-{image_version}"
            found_old = container_vuln_helper.wait_until_image_tag_appear(image_registry=image_registry_domain,
                                                                          ecr_repo=repo_name,
                                                                          image_tag=image_tag,
                                                                          timeout=30)
            found_new = new_vuln_helper.wait_until_image_tag_appear_in_new_vuln_page(image_registry=image_registry_domain,
                                                                                     ecr_repo=repo_name,
                                                                                     image_tag=image_tag,
                                                                                     timeout=900)
            if not found_old:
                error_message.append(f"Failed to find {image_tag} inside Container Vulnerability")
            if not found_new:
                error_message.append(f"Failed to find {image_tag} inside new Vulnerability Dashboard")
    logger.debug(error_message)
    assert not error_message, f"Error: {error_message}"


def test_new_vuln_filter_by_image_tag(api_v1_client, build_images_and_push_to_ecr, random_id,
                                      onboard_container_registry, image_registry_domain):
    """Verify that new Vuln Dashboard Show Container Image->Image Tag works as expected.

    Given: AWS ECR deployed, local docker images built and pushed to the ECR, and Container Registry is added to Lacework
    When: Using Show Container Image -> Image Tag
    Then: Images added to the ECR should be listed

    Args:
        api_v1_client: API V1 client for interacting with the Lacework.
        random_id: Prefix of created resource names
        build_images_and_push_to_ecr: Built images that were pushed to ECR
        onboard_container_registry: Onboarded Container Registry INTG_GUID
        image_registry_domain: ECR domain including deployed region name
    """
    Integrations(api_v1_client).wait_until_container_registry_success(intg_guid=onboard_container_registry, timeout=6000)
    new_vuln_helper = NewVulnerabilityDashboardHelper(user_api=api_v1_client)
    error_message = []
    for os_version in docker_file_dict:
        repo_name = f"{random_id}-{os_version}"
        for image_version in docker_file_dict[os_version]:
            image_tag = f"{random_id}-{image_version}"
            images_returned = new_vuln_helper.fetch_container_images_by_tag(image_tag)
            found = False
            for image in images_returned:
                if image_registry_domain in image['IMAGE_REGISTRIES'] and repo_name in image['IMAGE_REPOSITORIES']:
                    found = True
                    break
            if not found:
                error_message.append(f"Not found image with tag = {image_tag} when using IMAGE TAG filter")
    logger.debug(error_message)
    assert not error_message, f"Error: {error_message}"


def test_new_image_found_in_vuln(api_v1_client, build_images_and_push_to_ecr, random_id, dockerfile_path, build_test_image,
                                 push_docker_image_to_ecr, onboard_container_registry, image_registry_domain, ecr_deploy_region):
    """Verify new image built and uploaded to ECR is scanned.

    Given: Images inside ECR are scanned, and container registry changed to Success status
    When: Building new image and pushing to ECR, and listing vulnerabilities after scanned
    Then: New Image added to the ECR should be listed

    Args:
        api_v1_client: API V1 client for interacting with the Lacework.
        random_id: Prefix of created resource names
        build_images_and_push_to_ecr: Built images that were pushed to ECR
        onboard_container_registry: Onboarded Container Registry INTG_GUID
        image_registry_domain: ECR domain including deployed region name
    """
    container_vuln_helper = ContainerVulnerabilitiesHelper(user_api=api_v1_client)
    new_vuln_helper = NewVulnerabilityDashboardHelper(user_api=api_v1_client)
    ecr_helper = ECRHelper(region=ecr_deploy_region)
    created_repo = []
    try:
        logger.info("Build new image, and push to ECR")
        for os_version in docker_file_dict:
            repo_name = f"{random_id}-{os_version}-new"
            ecr_helper.create_repository(repository_name=repo_name)
            created_repo.append(repo_name)
            for image_version in docker_file_dict[os_version]:
                new_image_name = f"{image_version}-new"
                docker_file_path = dockerfile_path(image_version)
                docker_image = build_test_image(docker_image_name=new_image_name, docker_file_path=docker_file_path)
                push_docker_image_to_ecr(docker_image, repo_name)

        logger.info("Wait until Lacework scanned all newly created repos")
        Integrations(api_v1_client).wait_until_container_scanned(intg_guid=onboard_container_registry, ecr_repo_name=created_repo[0], timeout=6000)
        logger.info("Check if all newly created images are scanned")
        error_message = []
        for os_version in docker_file_dict:
            repo_name = f"{random_id}-{os_version}-new"
            for image_version in docker_file_dict[os_version]:
                image_tag = f"{random_id}-{image_version}-new"
                found_old = container_vuln_helper.wait_until_image_tag_appear(image_registry=image_registry_domain,
                                                                              ecr_repo=repo_name,
                                                                              image_tag=image_tag,
                                                                              timeout=300)
                found_new = new_vuln_helper.wait_until_image_tag_appear_in_new_vuln_page(image_registry=image_registry_domain,
                                                                                         ecr_repo=repo_name,
                                                                                         image_tag=image_tag,
                                                                                         timeout=300)
                if not found_old:
                    error_message.append(f"Failed to find {image_tag} inside Container Vulnerability")
                if not found_new:
                    error_message.append(f"Failed to find {image_tag} inside New Vuln Dashboard")
        logger.debug(error_message)
        assert not error_message, f"Error: {error_message}"
    finally:
        for repo_name in created_repo:
            ecr_helper.cleanup_ecr(repo_name)
            ecr_helper.delete_repository(repository_name=repo_name)


def test_new_version_found_in_vuln(api_v1_client, build_images_and_push_to_ecr, random_id, dockerfile_path, build_test_image,
                                   push_docker_image_to_ecr, onboard_container_registry, image_registry_domain, ecr_deploy_region):
    """Verify new verions of images built and uploaded to ECR is scanned.

    Given: Images inside ECR are scanned, and container registry changed to Success status
    When: Building new image and pushing to ECR to existing repos, and listing vulnerabilities
    Then: New versions of Images added to the ECR should be listed

    Args:
        api_v1_client: API V1 client for interacting with the Lacework.
        random_id: Prefix of created resource names
        build_images_and_push_to_ecr: Built images that were pushed to ECR
        onboard_container_registry: Onboarded Container Registry INTG_GUID
        image_registry_domain: ECR domain including deployed region name
    """
    container_vuln_helper = ContainerVulnerabilitiesHelper(user_api=api_v1_client)
    new_vuln_helper = NewVulnerabilityDashboardHelper(user_api=api_v1_client)
    created_repo = []
    logger.info("Build new image, and push to ECR existing repos")
    for os_version in docker_file_dict:
        repo_name = f"{random_id}-{os_version}"
        created_repo.append(repo_name)
        for image_version in docker_file_dict[os_version]:
            new_image_name = f"{image_version}-new"
            docker_file_path = dockerfile_path(image_version)
            docker_image = build_test_image(docker_image_name=new_image_name, docker_file_path=docker_file_path)
            push_docker_image_to_ecr(docker_image, repo_name)
    logger.info("Check if all newly created images are scanned")
    error_message = []
    for os_version in docker_file_dict:
        repo_name = f"{random_id}-{os_version}"
        for image_version in docker_file_dict[os_version]:
            image_tag = f"{random_id}-{image_version}-new"
            found_old = container_vuln_helper.wait_until_image_tag_appear(image_registry=image_registry_domain,
                                                                          ecr_repo=repo_name,
                                                                          image_tag=image_tag,
                                                                          timeout=3000)
            found_new = new_vuln_helper.wait_until_image_tag_appear_in_new_vuln_page(image_registry=image_registry_domain,
                                                                                     ecr_repo=repo_name,
                                                                                     image_tag=image_tag,
                                                                                     timeout=3000)
            if not found_old:
                error_message.append(f"Failed to find {image_tag} inside Container Vulnerability")
            if not found_new:
                error_message.append(f"Failed to find {image_tag} inside New Vuln Dashboard")
    logger.debug(error_message)
    assert not error_message, f"Error: {error_message}"
