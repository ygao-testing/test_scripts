import logging

from datetime import datetime
from fortiqa.libs.lw.apiv1.api_client.new_vuln.new_vuln import NewVulnerability
from fortiqa.libs.lw.apiv2.helpers.gerneral_helper import check_and_return_json_from_response

logger = logging.getLogger(__name__)


def generate_new_vuln_payload_and_query(api_v1_client, query_object, query_type, host_deployment_timestap: datetime = datetime.now()):
    """
    Helper function to generate New Vulnerability query payload, and execute the query

    Args:
        api_v1_client: API V1 Client
        query_object: New Vulnerability Query object
        query_type: Define the API endpoint, `host`, 'image`, 'package`, 'vulnerability`, 'unique_vuln_by_host' and 'unique_vuln_by_image'
    Returns:
        Json response
    """
    new_vuln_api = NewVulnerability(api_v1_client)
    generated_payload = new_vuln_api.generate_payload(new_vuln_object=query_object, anchored_timestamp=host_deployment_timestap)
    if query_type == "host":
        response = new_vuln_api.query_host(generated_payload)
    elif query_type == "package":
        response = new_vuln_api.query_packages(generated_payload)
    elif query_type == "image":
        response = new_vuln_api.query_images(generated_payload)
    elif query_type == "vulnerability":
        response = new_vuln_api.query_vulnerability(generated_payload)
    elif query_type == "unique_vuln_by_host":
        response = new_vuln_api.query_unique_vuln_by_host(generated_payload)
    elif query_type == "unique_vuln_by_image":
        response = new_vuln_api.query_unique_vuln_by_image(generated_payload)
    assert response.status_code == 200, f"Expected to get status code 200 from New Vulnerability Dashboard API, but got err: {response.text}"
    json_response = check_and_return_json_from_response(response)
    assert "errorLogId" not in json_response, f"Expect no error returned, but got {response.json()['cause']}"
    return json_response
