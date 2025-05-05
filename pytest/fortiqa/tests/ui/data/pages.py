"""Pages data"""

pages = {
    # DISCOVERY #
    "Dashboard": {
        "url": "/Dashboard",
        "left_menu": "Dashboardnew"},
    "Explorer": {
        "url": "/Explorer",
        "left_menu": "Explorernew"},
    "Resource Explorer": {
        "url": "/cloud/ResourceExplorer",
        "left_menu": "Resource Explorer"},
    "Resource Inventory": {
        "url": "/cloud/ResourceExplorer",
        "left_menu": "Resource Inventory"},

    # THREAT CENTER #
    "Alerts": {
        "url": "/monitor/AlertInbox",
        "left_menu": "Alerts"},
    # Cloud logs
    "AWS Cloudtrail": {
        "url": "/aws/CloudTrailDossier",
        "left_menu": "Cloud logs"},
    "Azure Activity Log": {
        "url": "/azure/ActivityLogDossier",
        "left_menu": "Cloud logs"},
    "GCP Audit Log": {
        "url": "/gcp/AuditLogDossier",
        "left_menu": "Cloud logs"},
    # Workloads
    "Workloads Hosts": {
        "url": "/host/BinaryDossier",
        "left_menu": "Workloads"},
    "Workloads Containers": {
        "url": "/container/ContainerDossier",
        "left_menu": "Workloads"},
    "Workloads Kubernetes": {
        "url": "/container/KubernetesDossier",
        "left_menu": "Workloads"},

    # RISK CENTER #
    # Attack path
    "Top work items": {
        "url": "/attackpath/AttackPathDashboard",
        "left_menu": "Attack path"},
    "Path investigation": {
        "url": "/attackpath/AttackPathAnalysis",
        "left_menu": "Attack path"},
    # Compliance
    "Compliance Cloud": {
        "url": "/cloud/CloudComplianceDashboard",
        "left_menu": "Compliance"},
    "Compliance Kubernetes": {
        "url": "/cloud/KubernetesDashboard",
        "left_menu": "Compliance"},

    "Identities": {
        "url": "/identities/overview",
        "left_menu": "Identities"},

    # Vulnerabilities
    "Vulnerabilities Vulnerabilities": {
        "url": "/vulnerabilities",
        "left_menu": "Vulnerabilities"},
    "Vulnerabilities Host": {
        "url": "/host/HostVulnerabilityDashboard",
        "left_menu": "Vulnerabilities"},
    "Vulnerabilities Containers": {
        "url": "/container/VulnerabilityDashboard",
        "left_menu": "Vulnerabilities"},
    "Vulnerabilities Exceptions": {
        "url": "/exceptions/VulnerabilityExceptionDashboard",
        "left_menu": "Vulnerabilities"},

    # Governance #
    "Policies": {
        "url": "/monitor/Policies",
        "left_menu": "Policies"},
    "Reports": {
        "url": "/AllReports",
        "left_menu": "Reports"},
    "Agents": {
        "url": "/monitor/AgentDossier",
        "left_menu": "Agents"},

    # Settings
    "Settings": {
        "url": "/settings/channels",
        "left_menu": "Settings"},
    "Channels": {
        "url": "/settings/channels",
        "left_menu": "Settings"},
    "Cloud accounts": {
        "url": "/settings/cloudaccounts",
        "left_menu": "Settings"},
    "Container registries": {
        "url": "/settings/containerregistries",
        "left_menu": "Settings"},
    "Security in Jira": {
        "url": "/settings/jiravulnintegration",
        "left_menu": "Settings"},
    "Resource groups": {
        "url": "/settings/resourcegroupsv2",
        "left_menu": "Settings"},
    "API keys": {
        "url": "/settings/apikeys",
        "left_menu": "Settings"},
    "Agent Tokens": {
        "url": "/settings/agents",
        "left_menu": "Settings"},
    "Risk score": {
        "url": "/settings/riskscores",
        "left_menu": "Settings"},
    "General": {
        "url": "/settings/general",
        "left_menu": "Settings"},
    "License": {
        "url": "/settings/license",
        "left_menu": "Settings"},
    "Subscription": {
        "url": "/settings/subscription",
        "left_menu": "Settings"},
    "Subscription Usage": {
        "url": "/settings/subscription-usage",
        "left_menu": "Settings"},
    "Audit logs": {
        "url": "/settings/auditlogs",
        "left_menu": "Settings"},
    "Roles": {
        "url": "/settings/accessroles",
        "left_menu": "Settings"},
    "User groups": {
        "url": "/settings/usergroups",
        "left_menu": "Settings"},
    "Users": {
        "url": "/settings/users",
        "left_menu": "Settings"},
    "My profile": {
        "url": "/settings/profile",
        "left_menu": "Settings"},
    "Onboarding": {
        "url": "/settings/onboarding",
        "left_menu": "Settings"},

    # Accounts
    "All accounts": {
        "url": "/investigation/accounts",
        "left_menu": ""}
}

tabs = {
    # "Workloads Hosts" page
    "Applications": "/host/BinaryDossier",
    "Files": "/host/FileDossier",
    "Machines": "/host/MachineDossier",
    "Networks": "/host/NetworkDossier",
    "Processes": "/host/ProcessDossier",
    "Users": "/host/UserDossier",

    # "Vulnerabilities Vulnerabilities" page
    "Overview": "/vulnerabilities/overview",
    "Top items": "/vulnerabilities/topitems",
    "Explore": "/vulnerabilities/explore/",

    # "Vulnerabilities Host" page
    "Host": "/host/HostVulnerabilityDashboard?groupBy=default",
    "CVE": "/host/HostVulnerabilityDashboard?groupBy=cve",
    "AMI ID": "/host/HostVulnerabilityDashboard?groupBy=data.MACHINE_TAGS.AmiId",
    "Account": "/host/HostVulnerabilityDashboard?groupBy=data.ACCOUNT",
    "Zone": "/host/HostVulnerabilityDashboard?groupBy=data.MACHINE_TAGS.Zone",
    "Package Name": "/host/HostVulnerabilityDashboard?groupBy=data.PACKAGE_TAGS.name",
    "Application (Windows)": "/host/HostVulnerabilityDashboard?groupBy=data.PACKAGE_TAGS.application",
    "Package Namespace": "/host/HostVulnerabilityDashboard?groupBy=data.PACKAGE_TAGS.namespace",

    # "Vulnerabilities Containers" page
    "Image ID": "/container/VulnerabilityDashboard",

    # "Explorer" page
    "Landing": "/Explorer",
    "Graph": "/Explorer/query"
}
