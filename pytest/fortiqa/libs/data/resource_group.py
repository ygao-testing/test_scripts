from dataclasses import dataclass
from typing import List, Union
from enum import Enum


class Operator(str, Enum):
    AND: str = 'AND'
    OR: str = 'OR'


@dataclass
class Filter:
    filter_name: str
    field: str
    operation: str
    value: List[str]


@dataclass
class ResourceGroupData:
    operator: Operator
    children: List[Union['ResourceGroupData', Filter]]

    @staticmethod
    def parse_from_lacework_api(data: dict) -> Union['ResourceGroupData', Filter]:
        """
        Parses a resource group from the Lacework API response.

        This function takes a dictionary representing a single entry from the list of dictionaries
        returned by the Lacework API and parses it into a Group object.

        Args:
            data (dict): A dictionary containing the Lacework API response
            for a single resource group.

        Returns:
            Group: A Group object representing the parsed resource group.

        Example input:
            >>> data = {
            ...     "query": {
            ...         "filters": {
            ...             "filter1": {
            ...                 "field": "field1",
            ...                 "operation": "equals",
            ...                 "values": ["value1", "value2"]
            ...             }
            ...         },
            ...         "expression": {
            ...             "operator": "AND",
            ...             "children": [
            ...                 {"filterName": "filter1"}
            ...             ]
            ...         }
            ...     }
            ... }
            >>> group = Group.parse_from_lacework_api(data)
            >>> print(group)
        """
        filters = data.get("query", {}).get("filters", {})

        def create_filter(filter_name: str):
            f = filters[filter_name]
            filter_value = f.get("values", [])
            # sort values for consistency when comparing
            if isinstance(filter_value, list):
                filter_value.sort()
            return Filter(
                filter_name=filter_name,
                field=f.get("field"),
                operation=f.get("operation"),
                value=filter_value
            )

        def parse_expression(expr: dict) -> Union['ResourceGroupData', Filter]:
            if "filterName" in expr:
                return create_filter(expr["filterName"])
            children = [parse_expression(child) for child in expr["children"]]
            # Sort children by filter name for consistency when comparing
            children.sort(key=lambda x: x.filter_name if isinstance(x, Filter) else x.operator)
            return ResourceGroupData(
                operator=Operator(expr["operator"]),
                children=children
            )

        return parse_expression(data.get("query", {}).get("expression"))

    @staticmethod
    def parse_from_terraform(data: dict) -> 'ResourceGroupData':
        """
        Parses a resource group from a given Terraform data dictionary.
        Args:
            data (dict): A dictionary containing Terraform resource group data.
        Returns:
            Group: A Group object representing the parsed resource group.
        Example input:
            >>> data = {
            ...     "group": [
            ...         {
            ...             "operator": "AND",
            ...             "filter": [
            ...                 {
            ...                     "filter_name": "filter1",
            ...                     "field": "field1",
            ...                     "operation": "equals",
            ...                     "value": ["value1", "value2"]
            ...                 }
            ...             ],
            ...             "group": [
            ...                 {
            ...                     "operator": "OR",
            ...                     "filter": [
            ...                         {
            ...                             "filter_name": "filter2",
            ...                             "field": "field2",
            ...                             "operation": "equals",
            ...                             "value": ["value3"]
            ...                         }
            ...                     ]
            ...                 }
            ...         }
            ...     ]
            ... }
            >>> group = Group.parse_from_terraform(data)
        """
        def parse_group(group_data: List[dict]) -> 'ResourceGroupData':
            group_element = group_data[0]
            children: List[Union[ResourceGroupData, Filter]] = []

            # Handle filters
            filters = group_element.get("filter", [])
            if not isinstance(filters, list):
                filters = [filters]
            for f in filters:
                if f:
                    filter_value = f.get("value", [])
                    # sort values for consistency when comparing
                    if isinstance(filter_value, list):
                        filter_value.sort()
                    children.append(Filter(
                        filter_name=f["filter_name"],
                        field=f["field"],
                        operation=f["operation"],
                        value=filter_value
                    ))

            # Handle nested groups
            groups = group_element.get("group", [])
            if groups:
                children.append(parse_group(groups))
            # Sort children by filter name for consistency when comparing
            children.sort(key=lambda x: x.filter_name if isinstance(x, Filter) else x.operator)
            return ResourceGroupData(
                operator=Operator(group_element["operator"]),
                children=children
            )

        return parse_group(data["group"])
