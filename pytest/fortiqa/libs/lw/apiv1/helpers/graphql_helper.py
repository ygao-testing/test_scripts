
import json
import logging

from typing import Dict, Any
from datetime import datetime, timedelta
from fortiqa.libs.lw.apiv1.payloads import GraphQLFilter

logger = logging.getLogger(__name__)


class GraphQLHelper:
    def __init__(self):
        self.query_string = """query Explorer($input: ResourceQueryInput!, $first: Int, $after: String, $last: Int, $before: String) {\n  resources(\n    input: $input\n    first: $first\n    after: $after\n    last: $last\n    before: $before\n  ) {\n    totalResults\n    pageInfo {\n      startCursor\n      hasPreviousPage\n      hasNextPage\n      endCursor\n      __typename\n    }\n    edges {\n      cursor\n      index\n      node {\n        ...StaticResourceFields\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\nfragment StaticResourceFields on ResourceV1 {\n  accessibleFromNetworkRange\n  accountAlias\n  accountId\n  alertIds\n  alertsSeverity\n  alertCategories\n  cloudProvider\n  complianceSeverity\n  endTime\n  hasAttackPath\n  hasInstanceProfileId\n  hasSshLateralMovement\n  hostname\n  hostRisk\n  identityRisk\n  internetExposed\n  numAlerts\n  numAttackPaths\n  numCompliance\n  numVulns\n  openPorts\n  organizationId\n  publicIpAddr\n  resourceGroupIds\n  resourceGroupNames\n  resourceId\n  resourceName\n  resourceTags {\n    key\n    value\n    __typename\n  }\n  resourceType\n  startTime\n  unifiedEntityRiskScore\n  unifiedEntityRiskScoreExplainability\n  unifiedEntityRiskExplainability {\n    hierarchicalExplanation {\n      descriptionBullets\n      descriptionText\n      heading\n      riskFactorScore\n      subFactors {\n        descriptionBullets\n        descriptionText\n        heading\n        riskFactorScore\n        subFactors {\n          descriptionBullets\n          descriptionText\n          heading\n          riskFactorScore\n          subFactors {\n            descriptionBullets\n            descriptionText\n            heading\n            riskFactorScore\n            __typename\n          }\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    riskFactorSummary {\n      apa\n      ciem\n      vulnerability\n      __typename\n    }\n    __typename\n  }\n  unifiedEntityRiskScoreSeverity\n  urn\n  lastDiscoveredTime\n  __typename\n}"""

    def generate_payload(self, graph_ql_filter: GraphQLFilter, start_time_string: str = "", end_time_string: str = ""):
        """
        Helper function to generate GraphQL payload
        :param graph_ql_filer: GraphQL filter object
        """
        if not start_time_string or not end_time_string:
            current_time = datetime.now()
            one_day_ago = current_time - timedelta(days=1)
            tomorrow = current_time + timedelta(days=1)
            start_time_string = one_day_ago.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            end_time_string = tomorrow.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        filter_type = graph_ql_filter.type
        default_template: Dict[str, Any] = {
            "operationName": "Explorer",
            "query": self.query_string,
            "variables": {
                "input": {
                    "endTime": end_time_string,
                    "startTime": start_time_string,
                    "filter": {
                        "where": {
                            "and": [
                                {
                                    "properties": {
                                        "type": filter_type
                                    }
                                }
                            ],
                        },
                    }
                },
                "first": 5000,
            }
        }
        for filter in graph_ql_filter.filters:
            if not filter.subfilters:
                if filter.operator is not None:
                    default_template['variables']['input']['filter']['where']['and'].append({
                        "properties": {
                            filter.key: {
                                filter.operator.value: filter.value
                            }
                        }
                    })
                else:
                    default_template['variables']['input']['filter']['where']['and'].append({
                        "properties": {
                            filter.key: filter.value
                        }
                    })
            elif filter.key in ["alerts", "complianceFindings", "vulnerabilityFindings"]:
                if "with" not in default_template['variables']['input']['filter']:
                    default_template['variables']['input']['filter']['with'] = {
                        "and": []
                    }
                for subfilter in filter.subfilters:
                    if subfilter.operator is not None:
                        default_template['variables']['input']['filter']['with']['and'].append({
                            "properties": {
                                filter.key: {
                                    "where": {
                                        "properties": {
                                            subfilter.key: {
                                                subfilter.operator.value: subfilter.value
                                            }
                                        }

                                    }
                                }
                            }
                        })
            else:
                for subfilter in filter.subfilters:
                    if subfilter.operator is not None:
                        default_template['variables']['input']['filter']['where']['and'].append({
                            "properties": {
                                filter.key: {
                                    subfilter.key: {
                                        subfilter.operator.value: subfilter.value
                                    }
                                }
                            }
                        })
        if graph_ql_filter.connection is not None:
            if "with" not in default_template['variables']['input']['filter']:
                default_template['variables']['input']['filter']['with'] = {
                    "and": []
                }
            default_template['variables']['input']['filter']['with']['and'].append({
                "properties": {
                    "connectsTo": {
                        "where": {
                            "and": [
                                {
                                    "properties": {
                                        "type": graph_ql_filter.connection.type
                                    }
                                }
                            ]
                        }
                    }
                }
            })

        logger.info(f"Generated payload: {json.dumps(default_template, indent=2)}")
        return default_template
