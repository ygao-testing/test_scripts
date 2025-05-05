import pytest
import logging
import string
import os
import random
import tftest
import time

from datetime import datetime


logger = logging.getLogger(__name__)

random_id = ''.join(random.choices(string.ascii_letters, k=4))
tf_owner_prefix = f'cloudlog-{random_id.lower()}'


@pytest.fixture(scope='package')
def cloudlog_tf_root(request) -> str:
    """Fixture returns root folder for lacework provider TF modules."""
    root = os.path.join(request.config.rootdir, '../terraform/cloudlog/')
    return root


def apply_tf_modules(module_list: list[str], module_root: str) -> dict[str, dict]:
    """Deploys list of terraform modules.

    Args:
        module_list: list of TF module names.
        module_root: root folder where all TF modules are located.

    Returns: dict[str, dict]
    """
    hosts = {}
    for tf_module in module_list:
        tf = tftest.TerraformTest(tf_module, module_root)
        try:
            tf.setup()
            tf.apply(tf_vars={
                'OWNER': tf_owner_prefix.replace("_", "-").replace('.', '')
            })
        except Exception:
            logger.exception(f'Failed to deploy TF module {tf_module}')
            raise
        finally:
            hosts[tf_module] = {'tf': tf, 'deployment_time': time.monotonic(), 'deployment_timestamp': datetime.now()}
    return hosts


def destroy_tf_modules(tf_modules: dict) -> None:
    """Destroys list of terraform modules.

    Args:
        module_list: list of TF module names.
        module_root: root folder where all TF modules are located.
    """
    for tf_module in tf_modules:
        try:
            logger.info(f'Destroying {tf_module=}')
            tf_modules[tf_module]['tf'].destroy(tf_vars={
                'OWNER': tf_owner_prefix.replace("_", "-").replace('.', '')
            })
        except Exception:
            logger.exception(f'Failed to destroy TF module {tf_module}')
