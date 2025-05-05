import time
import logging

from fortiqa.libs.aws.s3 import S3Helper
from fortiqa.libs.aws.awshelper import AWSHelper

log = logging.getLogger(__name__)


class CloudformationHelper(AWSHelper):
    def __init__(self, region='us-west-2', aws_credentials: dict = {}):
        super().__init__(boto3_client="cloudformation", region=region, aws_credentials=aws_credentials)

    def create_stack(
        self,
        template_body: str,
        stack_name: str,
        capabilities: list = ['CAPABILITY_IAM'],
        parameters: list = []
    ) -> str:
        """Creates CF stack using give CF template.

        This method immediately returns stack ID, but doesn't wait for it to complete.
        """
        resp = self.client.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Capabilities=capabilities,
            Parameters=parameters
        )
        return resp['StackId']

    def create_stack_and_wait(
        self,
        template_body: str,
        stack_name: str,
        capabilities: list = ['CAPABILITY_IAM'],
        parameters: list = [],
    ) -> str:
        """Runs CFT and waits for it to complete.

        :param template_body: content of the cloudformation template
        :param capabilities: list of capabilities needed to create the stack
        :param parameters: list of parameter configuration needed to create stack, e.g. security_lake stack
        :return: value of stack_id
        """
        stack_id = self.create_stack(template_body, stack_name, capabilities, parameters)
        self.wait_for_create_complete(stack_id)
        return stack_id

    def delete_stack(self, stack_id: str) -> None:
        """Delete CF stack in AWS"""
        self.client.delete_stack(
            StackName=stack_id
        )

    def list_stack(self) -> dict:
        """List CF stack in AWS"""
        response = self.client.list_stacks()
        return response

    def delete_stack_and_wait(self, stack_id: str) -> None:
        """Delete CF stack in AWS and wait for 'DELETE_COMPLETE' status"""
        self.client.delete_stack(StackName=stack_id)
        self.wait_for_delete_complete(stack_id)

    def delete_stack_with_dependencies(self, stack_id: str) -> None:
        """Deletes S3 bucket created by CFT, then deletes CF stack itself.

        :param stack_id: CF stack ID or name
        """
        s3 = S3Helper(region=self.region, aws_credentials=self.aws_credentials)
        logging_bucket_name = self.get_stack_resource_by_logical_id(stack_id, 'LoggingS3Bucket')
        s3.delete_all_objects_in_bucket(logging_bucket_name)
        s3.delete_bucket(logging_bucket_name)
        self.delete_stack(stack_id)
        self.wait_for_delete_complete(stack_id)

    def wait_for_status(self, stack_id: str, expected_status: str, timeout: int = 120) -> bool:
        """Continuously checks CF stack status until it matches expected_status"""
        complete = False
        timed_out = False
        start_time = time.monotonic()
        stack_status = None
        while not complete and not timed_out:
            time_passed = time.monotonic() - start_time
            timed_out = (time_passed > timeout)
            logging.info(f"wait for stack to complete, remaining time to time out {timeout - round(time_passed)} seconds ")
            stack_status = self.get_stack_status(stack_id)
            logging.info(f"stack_status={stack_status}")
            complete = stack_status == expected_status
            if not timed_out:
                time.sleep(10)
        if complete:
            log.info(f"{stack_id} created/deleted successfully. Stack info: {self.client.describe_stacks(StackName=stack_id)}")
            return complete
        else:
            raise TimeoutError(f"Timed out waiting for status {expected_status} for {stack_id}. Actual status was {stack_status}")

    def wait_for_create_complete(self, stack_id: str, timeout: int = 1200) -> bool:
        """Continuously checks CF stack status until it matches 'CREATE_COMPLETE'"""
        return self.wait_for_status(stack_id, expected_status="CREATE_COMPLETE", timeout=timeout)

    def wait_for_delete_complete(self, stack_id: str, timeout: int = 1200) -> bool:
        """Continuously checks CF stack status until it matches 'DELETE_COMPLETE'"""
        return self.wait_for_status(stack_id, expected_status="DELETE_COMPLETE", timeout=timeout)

    def wait_for_rollback_complete(self, stack_id: str, timeout: int = 1200) -> bool:
        """Continuously checks CF stack status until it matches 'ROLLBACK_COMPLETE'"""
        return self.wait_for_status(stack_id, expected_status="ROLLBACK_COMPLETE", timeout=timeout)

    def get_stack_status(self, stack_id: str) -> str:
        """Return StackStatus field of the stack with the given ID/name"""
        resp = self.client.describe_stacks(StackName=stack_id)
        selected_stacks = filter(lambda s: s["StackId"] == stack_id, resp['Stacks'])
        stack = list(selected_stacks)[0]
        return stack["StackStatus"]

    def get_create_failed_status_reasons(self, stack_id: str) -> list[str]:
        """Returns list of 'error' messages corresponding to 'CREATE_FAILED' events"""
        events = self.client.describe_stack_events(StackName=stack_id)['StackEvents']
        return [e['ResourceStatusReason'] for e in events if e['ResourceStatus'] == 'CREATE_FAILED']

    def get_stack_outputs(self, stack_id: str) -> list:
        """Return Outputs field of the stack with the given ID/name"""
        resp = self.client.describe_stacks(StackName=stack_id)
        selected_stacks = filter(lambda s: s["StackId"] == stack_id, resp['Stacks'])
        stack = list(selected_stacks)[0]
        if 'Outputs' not in stack:
            return []
        return stack['Outputs']

    def get_stack_resource_by_logical_id(self, stack_id: str, logical_res_id: str):
        """
        :param stack_id:
          The name or the unique stack ID that is associated with the stack
        :param logical_res_id:
          The logical name of the resource as specified in the template.
          Example: "LoggingS3Bucket"
        """
        resp = self.client.describe_stack_resources(
            StackName=stack_id,
            LogicalResourceId=logical_res_id,
        )
        return resp['StackResources'][0]['PhysicalResourceId']
