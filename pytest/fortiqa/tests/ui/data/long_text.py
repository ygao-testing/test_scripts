"""Long texts for different data sections"""

# Dashboard #
dashboard_empty_data = {
    "Identities": "No data found\nEnsure that resources exist for the selected resource groups\nModify configuration",
    "Compliance": "",
    "Host vulnerabilities": "Data empty because of filter\nThis metric data has been filtered out based on the configuration\nModify configuration"
}

# Vulnerabilities #
vulnerabilities_tooltips = {
    # Total status over time
    "Comparison of host vulnerabilities": "The comparison of today's host vulnerabilities against host vulnerabilities from the start of the selected time period. The difference from the start of the time period is shown in the legend.",
    "Comparison of container vulnerabilities": "The comparison of today's container vulnerabilities against container vulnerabilities from the start of the selected time period. The difference from the start of the time period is shown in the legend.",
    "Total at risk host vulnerabilities": "The comparison of today's at risk host vulnerabilities against host vulnerabilities from the start of the selected time period. The difference from the start of the time period is shown in the legend. At risk hosts are internet exposed and fixable.",
    "Total at risk container vulnerabilities": "The comparison of today's at risk container vulnerabilities against container vulnerabilities from the start of the selected time period. The difference from the start of the time period is shown in the legend. At risk container images are internet exposed and fixable.",
    # Trend
    "Host vulnerabilities over time": "The current state of known host vulnernability observations in your environment over time.",
    "Container vulnerabilities over time": "The current state of known container vulnernability observations in your environment over time.",
    # Top Items
    "Top vulnerable container images": "Top vulnerable container images, sorted by severity of vulnerabilities",
    "Top vulnerable hosts": "Top vulnerable hosts, sorted by severity of vulnerabilities",
    "Top vulnerabilities by impacted hosts": "Active vulnerabilities that were found in actively running hosts. Active vulnerabilities are vulnerabilities that are unpatched.",
    "Top vulnerabilities by impacted images": "Active vulnerabilities that were found in images with actively running containers. Active vulnerabilities are vulnerabilities that are unpatched.",
    "Top fixable packages in containers": "The top fixable packages in images with actively running containers with the most vulnerabilities. Prioritize updating these packages to resolve the most active vulnerabilities.",
    "Top fixable packages in hosts": "The top fixable packages in actively running hosts with the most vulnerabilities. Prioritize updating these packages to resolve the most active vulnerabilities.",
    "Most recent vulnerable hosts": "Top actively running hosts found vulnerable since the last 3 days, sorted by severity of vulnerabilities",
    "Most recent vulnerable container images": "Top actively running container images found vulnerable since the last 3 days, sorted by severity of vulnerabilities",
    # Latest status
    "Unscanned images with active containers": "The current state of unscanned images that have active containers. Images can have a scan status of unscanned, success, partial, and error.",
    "Latest at risk container images": "The current state of at risk container vulnerabilities by severity. At risk container images are internet exposed and fixable.",
    "Latest at risk hosts": "The current state of at risk host vulnerabilities by severity. At risk hosts are internet exposed and fixable.",
    "Host coverage type": "The current distribution of coverage types for hosts. This distribution is based off the last time an agent sent a heartbeat.",
    "OS EOL dates": "The distribution of operating systems used by actively running hosts and their end of life dates.",
    # Trends by resource groups
    "Host vulnerabilities at risk": "The trend of at risk host vulnerabilities. At risk hosts are internet exposed and fixable.",
    "Container vulnerabilities at risk": "The trend of at risk container vulnerabilities. At risk container images are internet exposed and fixable.",
}
