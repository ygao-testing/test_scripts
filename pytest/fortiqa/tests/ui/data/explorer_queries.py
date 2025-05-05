"""Explorer queries"""

saved_queries = {
    "Show all hosts with log4j vulnerability": {
        "query_text": "Name\nShow all hosts with log4j vulnerability\n"
                      "Query ID\n1log4j\n"
                      "Query Summary\nShow Hosts that meet conditions: (Vulnerabilities > Id is equal to CVE-2021-44228)\n"
                      "Created by\nLacework",
        "query_data": "SHOW\nHosts\n"
                      "WHERE\nVulnerabilities > Id is equal to CVE-2021-44228"},
    "Show all hosts with vulnerability related to xz-utils package": {
        "query_text": "Name\nShow all hosts with vulnerability related to xz-utils package\n"
                      "Query ID\n2xzutils\n"
                      "Query Summary\nShow Hosts that meet conditions: (Vulnerabilities > Package Name is equal to xz-utils)\n"
                      "Created by\nLacework",
        "query_data": "SHOW\nHosts\n"
                      "WHERE\nVulnerabilities > Package Name is equal to xz-utils"},
    "Show all hosts exposed to the internet and running active packages with critical or high severity vulnerabilities": {
        "query_text": "Name\nShow all hosts exposed to the internet and running active packages with critical or high severity vulnerabilities\n"
                      "Query ID\n3internetexposedpackageactive\n"
                      "Query Summary\nShow Hosts that meet conditions: (Vulnerabilities > Severity is in [Critical, High]) AND (Internet Exposed is True) AND (Vulnerabilities > Package Status is in ACTIVE)\n"
                      "Created by\nLacework",
        "query_data": "SHOW\nHosts\n"
                      "WHERE\nVulnerabilities > Severity is in (Critical or High)\n"
                      "AND\nInternet Exposed is equal to True\n"
                      "AND\nVulnerabilities > Package Status is in ACTIVE"},
    "Show high risk hosts with SSH port open and exposed to the public internet due to inbound access": {
        "query_text": "Name\nShow high risk hosts with SSH port open and exposed to the public internet due to inbound access\n"
                      "Query ID\n4highrisk\n"
                      "Query Summary\nShow Hosts that meet conditions: (Internet Exposed to CIDR range is any of 0.0.0.0/0) AND (Open Ports is any of 22) AND (Risk > Score is greater than or equal to 8)\n"
                      "Created by\nLacework",
        "query_data": "SHOW\nHosts\n"
                      "WHERE\nInternet Exposed to CIDR range is any of 0.0.0.0/0\n"
                      "AND\nOpen Ports is any of 22\n"
                      "AND\nRisk > Score is greater than or equal to 8"},
    "Show all AWS identities that can access storage assets": {
        "query_text": "Name\nShow all AWS identities that can access storage assets\n"
                      "Query ID\n5showIdentitiesWithAccessToResource\n"
                      "Query Summary\nShow Identities that meet conditions: (Cloud Service Provider is in AWS)\n"
                      "Created by\nLacework",
        "query_data": "SHOW\nIdentities\n"
                      "WHERE\nCloud Service Provider is in AWS\n"
                      "SHOW\nStorage Assets"},
    "Show all hosts that are internet exposed to a specific CIDR range behind a VPN or other gateways": {
        "query_text": "Name\nShow all hosts that are internet exposed to a specific CIDR range behind a VPN or other gateways\n"
                      "Query ID\n6intexposedtoCidr\n"
                      "Query Summary\nShow Hosts that meet conditions: (Internet Exposed to CIDR range is any of 0.0.0.0/0)\n"
                      "Created by\nLacework",
        "query_data": "SHOW\nHosts\n"
                      "WHERE\nInternet Exposed to CIDR range is any of 0.0.0.0/0"},
    "Show all storage assets of type AWS accessible via identity": {
        "query_text": "Name\nShow all storage assets of type AWS accessible via identity\n"
                      "Query ID\n7showStorageThatCanBeAccessedByIdentity\n"
                      "Query Summary\nShow Storage Assets that meet conditions: (Cloud Service Provider is in AWS)\n"
                      "Created by\nLacework",
        "query_data": "SHOW\nStorage Assets\n"
                      "WHERE\nCloud Service Provider is in AWS\n"
                      "SHOW\nIdentities"},
    "Show all hosts that may lead to lateral movement because of SSH keys": {
        "query_text": "Name\nShow all hosts that may lead to lateral movement because of SSH keys\n"
                      "Query ID\n8lateralmovement\n"
                      "Query Summary\nShow Hosts that meet conditions: (Lateral SSH Movement is True)\n"
                      "Created by\nLacework",
        "query_data": "SHOW\nHosts\n"
                      "WHERE\nLateral SSH Movement is equal to True"}
}
