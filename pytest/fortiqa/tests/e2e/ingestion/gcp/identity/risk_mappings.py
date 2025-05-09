import logging

logger = logging.getLogger(__name__)

# Define GCP IAM to role mapping
GCP_IAM_TO_ROLE = {
    "roles/editor": ["role1"],
    "roles/storage.admin": ["role2"],
    "roles/storage.objectViewer": ["role3"],
    "roles/secretmanager.admin": ["role4"],
    "roles/compute.admin": ["role5"],
    "roles/cloudfunctions.admin": ["role6"],
    "roles/owner": ["role7", "Zhenxiao Qi", "testgroup"],
}

# Pre-defined user accounts
GCP_USER_ACCOUNT_EMAILS = {
    "Zhenxiao Qi": "zhenxiao@autotest.staging.forticasb.com"
}

# Pre-defined groups
GCP_GROUP_ACCOUNT_EMAILS = {
    "testgroup": "testgroup@autotest.staging.forticasb.com"
}

# Define GCP risk mappings based on roles
GCP_RISKS_MAPPING = {
    "ALLOWS_FULL_ADMIN": [
        "roles/owner"
    ],
    # Roles that can create/modify IAM resources
    "ALLOWS_IAM_WRITE": [
        "roles/owner",
        "roles/storage.admin",
        "roles/cloudfunctions.admin",
        "roles/secretmanager.admin",
        "roles/compute.admin"
    ],
    "ALLOWS_COMPUTE_EXECUTE": [
        "roles/owner",
        "roles/cloudfunctions.admin",
        "roles/compute.admin"
    ],
    # Roles that provide storage write access
    "ALLOWS_STORAGE_WRITE": [
        "roles/owner",
        "roles/storage.admin",
    ],
    # Roles that provide storage read access
    "ALLOWS_STORAGE_READ": [
        "roles/owner",
        "roles/storage.admin",
        "roles/storage.objectViewer"
    ],
    # Roles that can manage secrets
    "ALLOWS_SECRETS_READ": [
        "roles/owner",
        "roles/secretmanager.admin"
    ],
}
