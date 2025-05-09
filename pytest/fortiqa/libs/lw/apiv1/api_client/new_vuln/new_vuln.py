import logging
import requests
import json
import fortiqa.libs.lw.apiv1.api_client.new_vuln.payloads as payloads

from typing import Any, Dict
from datetime import datetime, timedelta
from fortiqa.libs.lw.apiv1.api_client.api_v1_client import ApiV1Client
from fortiqa.libs.lw.apiv1.api_client.new_vuln.payloads import HostReturnFields, PackageReturnFields, \
        ImageReturnFields, PackageReturnFieldsAssociateWithHost, NewVulnDataclass, ResourceTypes, ComparisonOperator, \
        VulnerabilitiesReturnFields, UniqueVulnByImageReturnFields, UniqueVulnByHostReturnFields

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class NewVulnerability:
    """A class to interact with the Vulnerability V1 API."""

    def __init__(self, api_v1_client: ApiV1Client, limit: int = 5000, pageSize: int = 5000) -> None:
        """Initializes the NewVulnerability class.

        Args:
            api_v1_client (api_v1_client): An instance of the API v1 client for sending requests.
        """
        self._user_api = api_v1_client
        self._api_url = f"{api_v1_client.url}/query/v2/data/vulnpres"
        self._param = f"limit={limit}&pageSize={pageSize}"

    def query_vulnerability(self, payload: dict) -> requests.Response:
        """
        Query Vulnerabilities (Show Vulnerabilities in UI)

        Args:
            payload: Query Payload.
            example:
            {
                "returns": [
                    {
                        "field": "CVSS_SCOPE"
                    }
                ],
                "filters": [
                    {
                        "field": "VulnPres_VulnFilters.SEVERITY",
                        "type": "in",
                        "values": [
                            "1",
                            "2",
                            "3"
                        ]
                    }
                ],
                "namedSets": [
                    "LACEWORK_RESOURCE_GROUP_ALL_AWS",
                ],
                "paramInfo": [
                    {
                        "name": "StartTimeRange",
                        "value": "1732089600000"
                    },
                    {
                        "name": "EndTimeRange",
                        "value": "1739951999999"
                    },
                    {
                        "name": "ActiveFilterCards",
                        "value": "VulnPres_VulnFilters"
                    }
                ]
            }

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.debug("query_vulnerability()")
        response = self._user_api.post(url=f"{self._api_url}/vulnsWithAggregations?{self._param}", payload=payload)
        # logger.debug(f"Query Vulnerability response: {response.text}")
        return response

    def query_host(self, payload: dict) -> requests.Response:
        """
        Query Hosts (Show Hosts in UI)

        Args:
            payload: Query Payload.
            example:
            {
                "returns": [],
                "filters": [],
                "namedSets": [],
                "paramInfo": [
                    {
                        "name": "StartTimeRange",
                        "value": ""
                    },
                    {
                        "name": "EndTimeRange",
                        "value": ""
                    }
                ]
            }

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.debug("query_host()")
        payload["returns"] = HostReturnFields.generate_return_payload()
        # logger.debug(f"Payloads: {json.dumps(payload['filters'], indent=2)}")
        response = self._user_api.post(url=f"{self._api_url}/hostsWithAggregations?{self._param}", payload=payload)
        # logger.debug(f"Query Hosts response: {response.text}")
        return response

    def query_packages(self, payload: dict) -> requests.Response:
        """
        Query Packages (Show Packages in UI)

        Args:
            payload: Query Payload.
            example:
            {
                "returns": [],
                "filters": [],
                "namedSets": [],
                "paramInfo": [
                    {
                        "name": "StartTimeRange",
                        "value": ""
                    },
                    {
                        "name": "EndTimeRange",
                        "value": ""
                    }
                ]
            }

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.debug("query_packages()")
        # logger.debug(f"Payloads: {json.dumps(payload['filters'], indent=2)}")
        payload["returns"] = PackageReturnFields.generate_return_payload()
        response = self._user_api.post(url=f"{self._api_url}/packagesByNameWithAggregations?{self._param}", payload=payload)
        # logger.debug(f"Query Packages response: {response.text}")
        return response

    def query_packages_specifically(self, payload: dict) -> requests.Response:
        """
        Query Packages associate specifically with a host

        Args:
            payload: Query Payload.
            example:
            {
                "returns": [],
                "filters": [],
                "namedSets": [],
                "paramInfo": [
                    {
                        "name": "StartTimeRange",
                        "value": ""
                    },
                    {
                        "name": "EndTimeRange",
                        "value": ""
                    }
                ]
            }

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.debug("query_packages_with_mid()")
        # logger.debug(f"Payloads: {json.dumps(payload['filters'], indent=2)}")
        payload["returns"] = PackageReturnFieldsAssociateWithHost.generate_return_payload()
        response = self._user_api.post(url=f"{self._api_url}/packageInstancesWithAggregations?{self._param}", payload=payload)
        # logger.debug(f"Query Packages response: {response.text}")
        return response

    def query_images(self, payload: dict) -> requests.Response:
        """
        Query Images (Show Container Images in UI)

        Args:
            payload: Query Payload.
            example:
            {
                "returns": [],
                "filters": [],
                "namedSets": [],
                "paramInfo": [
                    {
                        "name": "StartTimeRange",
                        "value": ""
                    },
                    {
                        "name": "EndTimeRange",
                        "value": ""
                    }
                ]
            }

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.debug("query_images()")
        # logger.debug(f"Payloads: {json.dumps(payload['filters'], indent=2)}")
        payload["returns"] = ImageReturnFields.generate_return_payload()
        response = self._user_api.post(url=f"{self._api_url}/imagesWithAggregations?{self._param}", payload=payload)
        # logger.debug(f"Query Images response: {response.text}")
        return response

    def query_unique_vuln_by_host(self, payload: dict) -> requests.Response:
        """
        Query Unique Vulnerabilities by Host (Show Unique vulnerability by host in UI)

        Args:
            payload: Query Payload.
            example:
            {
                "returns": [],
                "filters": [],
                "namedSets": [],
                "paramInfo": [
                    {
                        "name": "StartTimeRange",
                        "value": ""
                    },
                    {
                        "name": "EndTimeRange",
                        "value": ""
                    }
                ]
            }

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.debug("query_unique_vuln_by_host()")
        # logger.debug(f"Payloads: {json.dumps(payload['filters'], indent=2)}")
        response = self._user_api.post(url=f"{self._api_url}/hostVulnObservations?{self._param}", payload=payload)
        # logger.debug(f"Query Unique Vulnerabilities by Host response: {response.text}")
        return response

    def query_unique_vuln_by_image(self, payload: dict) -> requests.Response:
        """
        Query Unique Vulnerabilities by Container Image (Show Unique vulnerability by container image in UI)

        Args:
            payload: Query Payload.
            example:
            {
                "returns": [],
                "filters": [],
                "namedSets": [],
                "paramInfo": [
                    {
                        "name": "StartTimeRange",
                        "value": ""
                    },
                    {
                        "name": "EndTimeRange",
                        "value": ""
                    }
                ]
            }

        Returns:
            requests.Response: The response object from the API call.
        """
        logger.debug("query_unique_vuln_by_image()")
        # logger.debug(f"Payloads: {json.dumps(payload['filters'], indent=2)}")
        response = self._user_api.post(url=f"{self._api_url}/imageVulnObservations?{self._param}", payload=payload)
        # logger.debug(f"Query Unique Vulnerabilities by Container Image response: {response.text}")
        return response

    def generate_payload(self, new_vuln_object: NewVulnDataclass, anchored_timestamp: datetime = datetime.now()):
        """
        Helper function to generate New Vulnerability payload
        :param new_vuln_object: New Vulnerability filter object
        """
        start_date = anchored_timestamp - timedelta(hours=10)
        end_date = anchored_timestamp + timedelta(hours=10)
        template: Dict[str, Any] = {
            "paramInfo": [
                {
                    "name": "StartTimeRange",
                    "value": int(start_date.timestamp() * 1000.0),
                },
                {
                    "name": "EndTimeRange",
                    "value": int(end_date.timestamp() * 1000.0)
                }
            ],
            "namedSets": ResourceTypes.all_resource_types()
        }
        for filter in new_vuln_object.filters:
            type = filter.type
            key = filter.key
            operator = filter.operator
            if not filter.value:
                raise Exception("No value provided")
            if filter.type == "ResourceTypes":
                template['namedSets'] = filter.value
            else:
                if 'filters' not in template:
                    template['filters'] = []
                cls = getattr(payloads, type)
                field_value = getattr(cls, key.strip())
                current_filter = {}
                current_filter['field'] = field_value
                current_filter['type'] = operator.value
                if operator in [ComparisonOperator.IS_ANY_OF, ComparisonOperator.IS_IN, ComparisonOperator.IS_NOT_ANY_OF]:
                    if isinstance(filter.value, list):
                        current_filter['values'] = filter.value
                    else:
                        current_filter['values'] = [filter.value]
                elif key == "HOST_NAME" and operator == ComparisonOperator.IS_EQUAL_TO:
                    current_filter['type'] = ComparisonOperator.IS_IN.value
                    current_filter['values'] = [filter.value]
                elif key == "MACHINE_TAGS" and isinstance(filter.value, dict):
                    current_filter['jpath'] = filter.value['tag_name']
                    current_filter['value'] = filter.value['tag_value']
                elif operator in [ComparisonOperator.STARTS_WITH, ComparisonOperator.ENDS_WITH, ComparisonOperator.CONTAINS]:
                    current_filter['type'] = "ilike"
                    match operator:
                        case ComparisonOperator.STARTS_WITH:
                            current_filter['value'] = f"{filter.value}*"
                        case ComparisonOperator.ENDS_WITH:
                            current_filter['value'] = f"*{filter.value}"
                        case ComparisonOperator.CONTAINS:
                            current_filter['value'] = f"*{filter.value}*"
                else:
                    current_filter['value'] = filter.value
            template['filters'].append(current_filter)
        query_entity = new_vuln_object.type.value
        match query_entity:
            case "hosts":
                template['returns'] = HostReturnFields.generate_return_payload()
                template['paramInfo'].append({
                    "name": "ActiveFilterCards",
                    "value": "VulnPres_HostFilters,VulnPres_VulnFilters"
                })
            case "cves":
                template['returns'] = VulnerabilitiesReturnFields.generate_return_payload()
                template['paramInfo'].append({
                    "name": "ApplyFiltersByIntersection",
                    "value": ""
                })
                template['paramInfo'].append({
                    "name": "ActiveFilterCards",
                    "value": "VulnPres_VulnFilters,VulnPres_VulnObservationFilters"
                })
            case "container_images":
                template['returns'] = ImageReturnFields.generate_return_payload()
                template['paramInfo'].append({
                    "name": "ApplyFiltersByIntersection",
                    "value": ""
                })
                template['paramInfo'].append({
                    "name": "ActiveFilterCards",
                    "value": "VulnPres_ImageFilters,VulnPres_VulnObservationFilters,VulnPres_VulnFilters"
                })
            case "packages":
                template['returns'] = PackageReturnFields.generate_return_payload()
                template['paramInfo'].append({
                    "name": "ApplyFiltersByIntersection",
                    "value": ""
                })
                template['paramInfo'].append({
                    "name": "ActiveFilterCards",
                    "value": "VulnPres_VulnFilters,VulnPres_VulnObservationFilters,VulnPres_HostFilters"
                })
            case "unique_vuln_by_host":
                template['returns'] = UniqueVulnByHostReturnFields.generate_return_payload()
                template['paramInfo'].append({
                    "name": "ActiveFilterCards",
                    "value": "VulnPres_VulnFilters"
                })
            case "unique_vuln_by_image":
                template['returns'] = UniqueVulnByImageReturnFields.generate_return_payload()
                template['paramInfo'].append({
                    "name": "ActiveFilterCards",
                    "value": "VulnPres_VulnFilters"
                })
        logger.debug(f"Generated Payload: {json.dumps(template, indent=2)}")
        return template
