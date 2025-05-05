
import json
import logging

from typing import Dict, Any
from datetime import datetime, timedelta
from fortiqa.libs.lw.apiv1.payloads import GraphQLFilter

logger = logging.getLogger(__name__)


class NewGraphQLHelper:
    def __init__(self):
        self.query_string = """query ExplorerV2($filter: ResourceFilter, $first: Int, $after: String, $last: Int, $before: String, $orderBy: [OrderField!]) {\n  resources(\n    filter: $filter\n    first: $first\n    after: $after\n    last: $last\n    before: $before\n    orderBy: $orderBy\n  ) {\n    totalResults\n    pageInfo {\n      startCursor\n      hasPreviousPage\n      hasNextPage\n      endCursor\n      __typename\n    }\n    edges {\n      cursor\n      rowOffset\n      node {\n        ...StaticResourceFieldsV2\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\nfragment StaticResourceFieldsV2 on Resource {\n  asOf\n  ... on ComputeResource {\n    accessibleFromNetworkRange\n    hasAttackPath\n    hasLateralSshMovement\n    hostname\n    openPorts\n    publicIpAddr\n    internetExposed\n    __typename\n  }\n  ... on IdentityResource {\n    hasInstanceProfile\n    __typename\n  }\n  accountAlias\n  accountId\n  cloudProvider\n  numAlerts\n  numAttackPaths\n  numCompliance\n  numVulns\n  organizationId\n  resourceGroupIds\n  resourceGroupNames\n  resourceId\n  resourceName\n  resourceTags {\n    key\n    value\n    __typename\n  }\n  resourceType: __typename\n  startTime\n  endTime: asOf\n  unifiedEntityRiskScore\n  unifiedEntityRiskScoreSeverity: unifiedEntityRiskSeverity\n  unifiedEntityRiskScoreExplainability: unifiedEntityRiskExplainability\n  urn\n  lastDiscoveredTime: asOf\n  __typename\n}"""

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
            "operationName": "ExplorerV2",
            "query": self.query_string,
            "variables": {
                "filter": {
                    "where": {
                        "and": [
                            {
                                "type": {
                                    "eq": filter_type
                                }
                            }
                        ],
                    },
                },
                "first": 5000,
                "orderBy": [
                    {
                        "field": "unifiedEntityRiskScore",
                        "order": "DESC"
                    }
                ]
            }
        }
        for filter in graph_ql_filter.filters:
            if not filter.subfilters:
                if filter.operator is not None:
                    default_template['variables']['filter']['where']['and'].append(
                        {
                            filter.key: {
                                filter.operator.value: filter.value
                            }
                        }
                    )
                else:
                    default_template['variables']['filter']['where']['and'].append(
                        {
                            filter.key: filter.value
                        }
                    )
            elif filter.key in ["VULNERABILITY_OBSERVATION", "COMPLIANCE_OBSERVATION", "alerts"]:
                entity_type = "observations" if filter.key in ["VULNERABILITY_OBSERVATION", "COMPLIANCE_OBSERVATION"] else filter.key
                if "with" not in default_template['variables']['filter']:
                    default_template['variables']['filter']['with'] = {
                        "and": [
                            {
                                entity_type: {
                                    "where": {
                                        "and": []
                                    }
                                }
                            }
                        ]
                    }
                elif not any(entity_type in sub_with for sub_with in default_template['variables']['filter']['with']['and']):
                    # Generated Payload has canAccess dictionary but no observations dictionary inside `and` list
                    default_template['variables']['filter']['with']['and'].append(
                        {
                            entity_type: {
                                "where": {
                                    "and": []
                                }
                            }
                        }
                    )
                for subfilter in filter.subfilters:
                    if subfilter.operator is not None:
                        for sub_with in default_template['variables']['filter']['with']['and']:
                            if entity_type in sub_with:
                                if entity_type == "observations":
                                    if filter.key == "COMPLIANCE_OBSERVATION":
                                        sub_with[entity_type]["where"]['and'].append(
                                            {
                                                "and": [
                                                    {
                                                        "type": {
                                                            "eq": filter.key
                                                        }
                                                    },
                                                    {
                                                        subfilter.key: {
                                                            subfilter.operator.value: subfilter.value
                                                        }
                                                    },
                                                    {
                                                        "status": {
                                                            "eq": "NON_COMPLIANT"
                                                        }
                                                    }
                                                ]
                                            }
                                        )
                                    else:
                                        sub_with[entity_type]["where"]['and'].append(
                                            {
                                                "and": [
                                                    {
                                                        "type": {
                                                            "eq": filter.key
                                                        }
                                                    },
                                                    {
                                                        subfilter.key: {
                                                            subfilter.operator.value: subfilter.value
                                                        }
                                                    }
                                                ]
                                            }
                                        )
                                else:
                                    sub_with[entity_type]["where"]['and'].append(
                                        {
                                            subfilter.key: {
                                                subfilter.operator.value: subfilter.value
                                            }
                                        }
                                    )
            else:
                for subfilter in filter.subfilters:
                    if subfilter.operator is not None:
                        if subfilter.key != "organizationId":
                            default_template['variables']['filter']['where']['and'].append({
                                f"{filter.key}{subfilter.key}": {
                                    subfilter.operator.value: subfilter.value
                                }
                            })
                        else:
                            default_template['variables']['filter']['where']['and'].append({
                                subfilter.key: {
                                    subfilter.operator.value: subfilter.value
                                }
                            })
        if graph_ql_filter.connection is not None:
            if "with" not in default_template['variables']['filter']:
                default_template['variables']['filter']['with'] = {
                    "and": []
                }
            default_template['variables']['filter']['with']['and'].append(
                {
                    "canAccess": {
                        "where": {
                            "and": [
                                {
                                    {
                                        "type": graph_ql_filter.connection.type
                                    }
                                }
                            ]
                        }
                    }
                }
            )

        logger.info(f"Generated payload: {json.dumps(default_template, indent=2)}")
        return default_template
