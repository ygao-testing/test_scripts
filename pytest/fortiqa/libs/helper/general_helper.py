import logging
import random
import time
from typing import TypeVar
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)
T = TypeVar('T')  # Generic type for the objects in the list


def select_random_from_list(items: list[T], description: str) -> T | None:
    """Selects a random item from a list and logs the process.

    Args:
        items (List[T]): List of items to select from.
        description (str): Description of the items for logging purposes.

    Returns:
        T | None : A randomly selected item or None if the list is empty.
    """
    if not items:
        logger.info(f"No {description} available to select from.")
        return None

    seed = time.time()
    random.seed(seed)
    logger.info(f"Using seed {seed} for random selection of {description}.")

    selected_item = random.choice(items)
    logger.info(f"Randomly selected {description}: {selected_item}")
    return selected_item


def generate_public_key():
    """
    Generates an RSA public key and returns it in PEM format.

    Returns:
        str: The public key in PEM format as a string.
    """
    # Generate a new RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Extract the public key
    public_key = private_key.public_key()

    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_pem.decode("utf-8")


def convert_private_ip_to_hostname(private_ip_address: str) -> str:
    """Convert instance's private IP address to hostName in format appear in Lacework

    Args:
        private_ip_address: Private IP address of the instance

    Returns:
        str : Hostname expected to appear in Lacework
    """
    return f"ip-{private_ip_address.replace('.', '-')}"
