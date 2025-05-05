import logging
import base64
import docker

from fortiqa.libs.aws.awshelper import AWSHelper


logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
log = logging.getLogger(__name__)


class ECRHelper(AWSHelper):
    """AWS ECR Helper functions using Boto3 client"""
    def __init__(self, region='us-west-2', aws_credentials: dict = {}):
        super().__init__(boto3_client="ecr", region=region, aws_credentials=aws_credentials)
        self.docker_client = docker.from_env()

    def authenticate_docker_with_ecr(self):
        """Authenticate Docker client with AWS ECR."""
        log.info("authenticate_docker_with_ecr()")
        response = self.client.get_authorization_token()
        auth_data = response["authorizationData"][0]
        token = auth_data["authorizationToken"]
        ecr_url = auth_data["proxyEndpoint"]

        username, password = self._decode_auth_token(token)
        self.docker_client.login(
            username=username,
            password=password,
            registry=ecr_url
        )
        log.info(f"Authenticated with ECR registry: {ecr_url}")
        return ecr_url

    @staticmethod
    def _decode_auth_token(token: str) -> list:
        """Helper function to decode the ECR authorization token."""
        log.info("decode_auth_token()")
        decoded_token = base64.b64decode(token).decode("utf-8")
        return decoded_token.split(":")

    def push_image_to_ecr(self, image_name: str, repository_name: str) -> str:
        """
        Push a Docker image to an ECR repository.

        :param image_name: Local Docker image name
        :param repository_name: ECR repository name in AWS

        :return: Local image name and tag after tagging
        """
        log.info("push_image_to_ecr()")
        ecr_url = self.authenticate_docker_with_ecr()
        ecr_repository_uri = f"{ecr_url.replace('https://', '')}/{repository_name}"
        log.info(f"Tagging image {image_name} as {ecr_repository_uri}...")
        self.docker_client.images.get(image_name).tag(ecr_repository_uri, tag=image_name)
        log.info(f"Pushing image {image_name} to {ecr_repository_uri}...")
        self.docker_client.images.push(ecr_repository_uri, tag=image_name, stream=False)
        log.info(f"Image {image_name} successfully pushed to {ecr_repository_uri}")
        return f"{ecr_repository_uri}:{image_name}"

    def list_images(self, repository_name: str) -> list:
        """
        List all images in the specified ECR repository.

        :param repository_name: The name of the ECR repository
        :return: A list of image tags in the repository
        """
        log.info(f"Listing images in ECR repository {repository_name}")
        paginator = self.client.get_paginator('describe_images')
        image_tags: list[str] = []
        for page in paginator.paginate(repositoryName=repository_name):
            for image_detail in page.get("imageDetails", []):
                image_tags.extend(
                    tag for tag in image_detail.get("imageTags", [])
                )
        log.info(f"Found images: {image_tags}")
        return image_tags

    def remove_image_from_ecr(self, image_tag: str, repository_name: str) -> None:
        """
        Remove a Docker image from an ECR repository.

        :param repository_name: The name of the ECR repository
        :param image_tag: The tag of the Docker image to remove
        """
        log.info(f"Remove image '{image_tag}' from ECR repository {repository_name}")
        response = self.client.batch_delete_image(
            repositoryName=repository_name,
            imageIds=[{"imageTag": image_tag}]
        )
        failures = response.get("failures", [])
        if failures:
            for failure in failures:
                log.error(f"Failed to delete image: {failure}")
        else:
            log.info(f"Image {image_tag} successfully removed from repository {repository_name}.")

    def cleanup_ecr(self, repository_name: str) -> None:
        """
        Remove all Docker images from an ECR repository.

        :param repository_name: The name of the ECR repository
        """
        log.info(f"Remove all images from {repository_name}")
        image_tags = self.list_images(repository_name)
        for image_tag in image_tags:
            self.remove_image_from_ecr(image_tag=image_tag, repository_name=repository_name)

    def create_repository(self, repository_name: str) -> str:
        """
        Create an ECR repository
        :param repository_name: ECR repository name in AWS
        """
        log.info("create_repository()")
        response = self.client.create_repository(repositoryName=repository_name)
        repository_uri = response["repository"]["repositoryUri"]
        log.info(f"ECR repository created: {repository_uri}")
        return repository_uri

    def delete_repository(self, repository_name: str, force: bool = False) -> None:
        """
        Delete an ECR repository
        :param repository_name: ECR repository name in AWS
        :param force: Whether to force the deletion of the repository (including images within it)
        """
        log.info(f"delete_repository() {repository_name}")
        response = self.client.delete_repository(repositoryName=repository_name, force=force)
        deleted_repository_name = response["repository"]["repositoryName"]
        log.info(f"ECR repository deleted: {deleted_repository_name}")

    def list_repositories(self) -> list:
        """List repositories inside AWS ECR"""
        log.info("list_repositories()")
        repositories = []
        paginator = self.client.get_paginator("describe_repositories")
        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                repositories.append(repo["repositoryUri"])
        log.info(f"Total repositories found: {repositories}")
        return repositories

    def check_if_repository_exist(self, repository_name: str) -> bool:
        """
        Check if a repository exists inside ECR
        :param repository_name: ECR repository name in AWS
        """
        log.info(f"check_if_repository_exist() for {repository_name}")
        all_repos = self.list_repositories()
        return repository_name in all_repos
