import json
import logging
import string
import random
import re

from fortiqa.libs.lw.apiv2.helpers.template_file_helper import TemplateFileHelper
from fortiqa.libs.lw.apiv1.api_client.downloads.downloads import Downloads
from fortiqa.libs.aws.cloudformation import CloudformationHelper


logger = logging.getLogger(__name__)


def fix_trailing_commas(raw_json):
    """
    Fixes trailing commas in a JSON string.

    :param raw_json: The original JSON string with potential trailing commas.
    :return: A cleaned JSON string with trailing commas removed.
    """
    fixed_json = re.sub(r",\s*([}\]])", r"\1", raw_json)
    return fixed_json


def _run_cloudformation_template(template, aws_credentials: dict = {}, aws_region: str = "us-west-2"):
    cft_helper = CloudformationHelper(aws_credentials=aws_credentials, region=aws_region)
    stack_id = None
    try:
        stack_id = cft_helper.create_stack(
            stack_name='fortiqa-' + ''.join(random.choice(string.ascii_uppercase) for _ in range(4)),
            template_body=json.dumps(json.loads(template)),
            capabilities=['CAPABILITY_NAMED_IAM'])
        cft_helper.wait_for_create_complete(stack_id)
        return stack_id
    except Exception:
        if stack_id:
            logger.error(cft_helper.get_create_failed_status_reasons(stack_id))
            cft_helper.delete_stack_and_wait(stack_id)
        raise


def generate_and_run_aws_eks_audit_cft(api_v2_client, aws_credentials: dict = {}):
    """Downloads and runs CloudFormation template for 'EKS Audit Log'."""
    resp = TemplateFileHelper(api_v2_client).get_aws_eks_audit_template()
    assert resp.status_code == 200
    return _run_cloudformation_template(template=resp.text, aws_credentials=aws_credentials)


def generate_and_run_aws_cloudtrail_cft(api_v2_client, aws_credentials: dict = {}):
    """Downloads and runs CloudFormation template for 'Cloudtrail'."""
    resp = TemplateFileHelper(api_v2_client).get_aws_cloudtrail_template()
    assert resp.status_code == 200
    return _run_cloudformation_template(template=resp.text, aws_credentials=aws_credentials)


def generate_and_run_aws_config_cft(api_v2_client, aws_credentials: dict = {}):
    """Downloads and runs CloudFormation template for 'Configuration'."""
    resp = TemplateFileHelper(api_v2_client).get_aws_config_template()
    assert resp.status_code == 200
    return _run_cloudformation_template(template=resp.text, aws_credentials=aws_credentials)


def generate_and_run_aws_agentless_cft(api_v1_client, intg_guid: str, aws_credentials: dict = {}):
    """Downloads and runs CloudFormation template for 'Configuration'."""
    resp = Downloads(api_v1_client).download_template_file(template_file_name="lacework-aws-agentless-direct-ng-auto.json", intgGuid=intg_guid)
    assert resp.status_code == 200, "Fail to download CloudFormation template"
    template_text = resp.text
    try:
        loaded_json = json.loads(template_text)
    except json.JSONDecodeError:
        loaded_json = json.loads(fix_trailing_commas(template_text))  # In the generated Json string, there are some trailing commas caused json.loads() failure
    loaded_json['Parameters']['Regions']['Default'] = "us-east-1, us-east-2, us-west-1, us-west-2"  # Change regions to US only
    loaded_json['Parameters']['VPCQuotaCheck']['Default'] = "Yes"
    return _run_cloudformation_template(template=json.dumps(loaded_json, indent=4), aws_credentials=aws_credentials)
