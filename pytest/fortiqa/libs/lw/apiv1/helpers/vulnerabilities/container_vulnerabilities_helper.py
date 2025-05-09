import json
import time
import logging

from datetime import datetime, timedelta
from copy import deepcopy
from fortiqa.libs.lw.apiv1.api_client.query_card.query_card import QueryCard

logger = logging.getLogger(__name__)


class ContainerVulnerabilitiesHelper:
    def __init__(self, user_api, deployment_time: datetime = datetime.now()):
        self.user_api = user_api
        start_date = deployment_time - timedelta(hours=5)
        end_date = deployment_time + timedelta(hours=5)
        self.payload_template = {
            "ParamInfo": {
                "StartTimeRange": int(start_date.timestamp() * 1000.0),
                "EndTimeRange": int(end_date.timestamp() * 1000.0),
                "EnableEvalDetailsMView": True
            },
        }

    def list_current_pod_namespaces(self) -> list:
        """Helper function to list all available namespaces inside lacework"""
        logger.debug("list_current_pod_namespaces()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Vuln_PodNamespaceView", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"Pod namespaces: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def list_k8s_clusters(self) -> list:
        """Helper function to list all k8s_clusters inside lacework"""
        logger.debug("list_k8s_clusters()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Vuln_K8sClusterView", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"K8s Clusters: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def list_vulnerability_stats_summary(self) -> list:
        """Helper function to list vulnerability stats summary for images"""
        logger.debug("list_vulnerability_stats_summary()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Vuln_StatsSummaryAll_MV", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"Vulnerability stats for images: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_recent_eval_summary(self) -> list:
        """Helper function to get recent eval summary(ALL Images)"""
        logger.debug("list_vulnerability_stats_summary()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Vuln_RecentEvalSummary_MV", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"Recent eval summary: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_recent_eval_summary_with_active_container(self) -> list:
        """Helper function to get recent eval summary with active container"""
        logger.debug("list_vulnerability_stats_summary()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Vuln_RecentEvalSummaryWithActiveContainer_MV", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"Recent eval summary with active container: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def wait_until_image_tag_appear(self, image_registry: str, ecr_repo: str, image_tag: str, timeout: int = 900) -> bool:
        """Waits for an image tag appear inside Container Vulnerability.

        Args:
            image_registry: Image registry in format of xxxx.dkr.ecr.us-west-1.amazonaws.com,
            ecr_repo: The ECR repo name inside AWS
            image_tag: The image tag used when pushing to ECR that needed to be found
            timeout: Max time until we wait for the image tag to be found to Lacework.

        Returns: True if found, False otherwise
        """
        image_found = False
        start_time = time.monotonic()
        timed_out = False
        while not timed_out and not image_found:
            time_passed = time.monotonic() - start_time
            timed_out = (time_passed > timeout)
            container_vuln_summary = self.fetch_recent_eval_summary()
            for data in container_vuln_summary:
                if data['IMAGE_REGISTRY'] == image_registry and data['IMAGE_REPO'] == ecr_repo and image_tag in data['IMAGE_TAGS']:
                    image_found = True
            if not image_found:
                time.sleep(120)
        if not image_found:
            logger.error(
                f'Image with tag {image_tag} in {ecr_repo} of {image_registry} was not returned by API'
                f'Last Container Vuln Summary: {container_vuln_summary}'
            )
            return False
        logger.debug(f"It took {time_passed} seconds until the image {image_tag} appears inside Container Vulnerability")
        return True

    def list_vulnerability_stats_cve_summary(self) -> list:
        """Helper function to list vulnerability stats CVE summary. It will output NUM of images for different severity"""
        logger.debug("list_vulnerability_stats_cve_summary()")
        payload = deepcopy(self.payload_template)
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Vuln_StatsSummaryCVETrend_MV", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"Vulnerability CVE trend stats for images: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_container_vulnerability_summary_by_eval_guid(self, eval_guid: str) -> list:
        """Fetch Container vulnerability summary by Eval Guid"""
        logger.debug("fetch_container_vulnerability_summary_by_eval_guid()")
        payload = deepcopy(self.payload_template)
        payload['ParamInfo']['EVAL_GUID'] = eval_guid  # type: ignore
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Vuln_ImageSummaryByEvalGuid_MV", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"Detail vuln info for the container: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']

    def fetch_recent_eval_by_image_id(self, image_id: str) -> list:
        """Fetch recent eval by a specific image id"""
        logger.debug("fetch_recent_eval_by_image_id()")
        payload = deepcopy(self.payload_template)
        payload['ParamInfo']['IMAGE_ID'] = image_id  # type: ignore
        query_card_response = QueryCard(self.user_api).exec_query_card(card_name="Vuln_RecentEvalByImageId", payload=payload)
        assert query_card_response.status_code == 200, f"Failed to execute the card, error: {query_card_response.text}"
        logger.debug(f"Fetch recent evals by {image_id=}: {json.dumps(query_card_response.json(), indent=2)}")
        return query_card_response.json()['data']
