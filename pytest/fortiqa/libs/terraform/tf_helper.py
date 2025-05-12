import os
import re
import time
import logging
import datetime
import tftest

from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class TFHelper():
    """Execute terraform operations, such as terraform modules deploy, destory and so on"""

    def __init__(self, tf_owner_prefix):
        """
        Initialize the TFHelper with test case path and random string.
        """
        self.tf_owner_prefix = tf_owner_prefix

    def apply_tf_modules(
        self,
        module_list: list[str],
        module_root: str,
        bucket_name: str,
        region: str,
        tags: dict | None = None
    ) -> dict[str, dict]:
        """
        Deploys a list of Terraform modules with dynamic backend configuration.

        Args:
            module_list: List of Terraform module paths.
            module_root: Root folder where all Terraform modules are located.
            bucket_name: Name of the S3 bucket for Terraform backend.
            region: AWS region for the S3 bucket.
            tags: Dictionary of tags to be applied, or None.

        Returns:
            dict[str, dict]: A dictionary containing module deployment details.
        """
        """
        Deploys a list of Terraform modules with dynamic backend configuration and resource tagging.

        This function initializes and applies Terraform modules dynamically. A unique backend state file
        key is generated using the 'tf_owner_prefix', module name, and a timestamp. By default, the 'OWNER'
        tag is applied to all Azure resources, while custom ingestion tags can optionally be provided
        for distinguishing deployments.

        Args:
            module_list (list[str]): List of Terraform module paths to be deployed.
            module_root (str): Root folder where all Terraform modules are located.
            bucket_name (str): Name of the S3 bucket used for Terraform backend state storage.
            region (str): Azure region where the S3 bucket resides.
            tags (dict | None): Optional custom tags to distinguish ingestion runs.

        Returns:
            dict[str, dict]: A dictionary containing module deployment details, where each key is a module name,
                            and the value contains:
                            - 'tf': The TerraformTest instance for the module.
                            - 'deployment_time': A monotonic timestamp captured **after deployment completes**.
                            - 'deployment_timestamp': The local system time recorded **after deployment completes**.
        """
        hosts = {}
        # Format the UTC timestamp in ISO 8601 format with milliseconds and 'Z'
        utc_now = datetime.now(timezone.utc)

        # Format the UTC timestamp in ISO 8601 format with milliseconds and 'Z'
        formatted_timestamp = utc_now.strftime(
            "%Y-%m-%dT%H:%M:%S") + f".{utc_now.microsecond // 1000:03d}Z"
        for tf_module in module_list:
            # to decide later if automatically obtain module_root recursively to replace passed parameter due to current duplicate module names
			# current_file_path = Path(__file__).resolve()
			# tf_modules_dir = os.path.join(current_file_path.parents[4], 'terraform')

            # module_matches = []
            # for root, dirs, _ in os.walk(tf_modules_dir):
            #     if tf_module in dirs:
            #         # Get the relative path of the target folder
            #         module_matches.append(os.path.join(tf_modules_dir, root))
            # # Handle the results
            # if not module_matches:
            #     raise FileNotFoundError(f"Module folder named '{tf_module}' not found.")
            # elif len(module_matches) > 1:
            #     raise ValueError(f"Multiple module folders named '{tf_module}' found: {module_matches}")
            # else:
            #     # Set the unique moudule folder path
            #     module_root = os.path.join(tf_modules_dir, module_matches[0])
            
            self.tf_file_check_and_add_backend_block(
                os.path.join(module_root, tf_module, "main.tf"))

            tf = tftest.TerraformTest(tf_module, module_root)
            try:
                # Generate a dynamic key for the state file
                dynamic_key = f"Terraform/test_{self.tf_owner_prefix}_{
                    formatted_timestamp}/{tf_module}/terraform.tfstate"
                logger.info(f"dynamic_key={dynamic_key}")

                # Setup with dynamic backend configuration
                backend_config = {
                    "bucket": bucket_name,
                    "key": dynamic_key,
                    "region": region,
                    "encrypt": "true"
                }
                logger.debug(f"Backend configuration: {backend_config}")
                tf_vars = {
                    'OWNER': self.tf_owner_prefix
                }
                # Pass the tags if provided
                if tags:
                    tf_vars['INGESTION_TAG'] = tags
                logger.info(f"Initializing terraform for  {tf_module} module")
                tf.setup(init_vars=backend_config, cleanup_on_exit=True)
                logger.info(f"Deploying resources for  {tf_module} module")
                # Run terraform apply and capture the output
                apply_output = tf.apply(tf_vars=tf_vars, capture_output=True)
                logger.info(f"Terraform apply output for module '{
                            tf_module}':\n{apply_output}")

                # Check for any errors in the output
                if "Error" in apply_output or "Failed" in apply_output:
                    logger.error(f"Partial failure detected in module '{
                                tf_module}'. Output:\n{apply_output}")

            except Exception as e:
                logger.exception(f'Failed to deploy TF module {
                                tf_module} error: {e}')
            finally:
                hosts[tf_module] = {
                    'tf': tf,
                    'deployment_time': time.monotonic(),
                    'deployment_timestamp': datetime.now(),
                    'backend_key': dynamic_key,
                }
        return hosts

    def destroy_tf_modules(self, tf_modules: dict) -> None:
        """Destroys the Terraform modules.
        Args:
            tf_modules: Dictionary containing Terraform modules information.
        """
        for tf_module in tf_modules:
            try:
                logger.info(f'Destroying {tf_module=}')
                tf_modules[tf_module]['tf'].destroy(tf_vars={
                    'OWNER': self.tf_owner_prefix
                })
            except Exception:
                logger.exception(f'Failed to destroy TF module {tf_module}')
                
    def tf_file_check_and_add_backend_block(self, file_path: str) -> tuple[bool, str]:
        """
        Check and add backend block to Terraform configuration file if not exists

        Args:
            file_path (str): Path to the Terraform configuration file

        Returns:
            tuple: (bool, str) - (whether modified, status message)
        """
        if not os.path.exists(file_path):
            return False, f"File '{file_path}' not found."

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()

            # Check if backend block already exists
            backend_pattern = r'^\s*terraform\s*{[^}]*backend\s*"[^"]+"\s*{[^}]*}[^}]*}'
            if re.search(backend_pattern, content, re.MULTILINE | re.DOTALL):
                return False, f"Backend configuration already exists in '{file_path}'."

            # Simple backend block template
            backend_block = 'terraform {\n  backend "s3" {}\n}'

            if not content.strip():
                # If file is empty, write the backend block directly
                new_content = backend_block
            else:
                # Check if terraform block exists
                terraform_block_pattern = r"^\s*terraform\s*{"
                if re.search(terraform_block_pattern, content, re.MULTILINE):
                    # Add backend to existing terraform block
                    new_content = re.sub(
                        r"(terraform\s*{)", r'\1\n  backend "s3" {}', content
                    )
                else:
                    # Add new terraform block at the beginning of the file
                    new_content = backend_block + "\n" + content

            # Write updated content back to file
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(new_content)

            return True, "Backend configuration added successfully."

        except Exception as e:
            return False, f"Error: Failed to add backend configuration: {str(e)}"
