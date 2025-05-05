import docker
import os
import logging

logger = logging.getLogger(__name__)


class DockerHelper:
    def __init__(self):
        # Initialize Docker client
        self.client = docker.from_env()

    def build_image(self, dockerfile_path, image_name, build_args=None):
        """
        Build a Docker image from a Dockerfile.

        :param dockerfile_path: Path to the Dockerfile.
        :param image_name: Name for the Docker image.
        :param build_args: Dictionary of build arguments, if any.
        :return: None
        """
        if not os.path.exists(dockerfile_path):
            raise FileNotFoundError(f"Dockerfile not found at: {dockerfile_path}")

        dockerfile_dir = os.path.dirname(dockerfile_path)
        with open(dockerfile_path, 'r') as file:
            logger.info(f"Building image '{image_name}' from Dockerfile {file} at {dockerfile_path}...")
            try:
                _, logs = self.client.images.build(
                    path=dockerfile_dir,
                    tag=image_name,
                    buildargs=build_args,
                    dockerfile=os.path.basename(dockerfile_path),
                    rm=True,
                    nocache=True
                )
                for log in logs:
                    if 'stream' in log:
                        logger.info(log['stream'].strip())
                logger.info(f"Image '{image_name}' built successfully.")
            except Exception as e:
                logger.info(f"Unexpected error: {e}")
                raise

    def list_images(self):
        """List all Docker images on the system."""
        images = self.client.images.list()
        return [image.tags for image in images]

    def remove_image(self, image_name):
        """Remove a Docker image by name."""
        try:
            self.client.images.remove(image=image_name, force=True)
            logger.info(f"Image '{image_name}' removed successfully.")
        except docker.errors.ImageNotFound:
            logger.info(f"Image '{image_name}' not found.")
        except Exception as e:
            logger.info(f"Error removing image: {e}")
