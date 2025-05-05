AWS_RISKS_MAPPING = {

    "ALLOWS_IAM_WRITE": ["IAMFullAccess", "AdministratorAccess"],
    "ALLOWS_STORAGE_WRITE": ["AmazonS3FullAccess", "AdministratorAccess"],
    "ALLOWS_STORAGE_READ": ["AmazonS3ReadOnlyAccess", "AmazonEC2FullAccess", "AdministratorAccess"],
    "ALLOWS_SECRETS_READ": ["SecretsManagerReadWrite", "AdministratorAccess"],
    "ALLOWS_COMPUTE_EXECUTE": ["AmazonEC2FullAccess", "AWSLambda_FullAccess", "AdministratorAccess"],
    "ALLOWS_CREDENTIAL_EXPOSURE": ["IAMFullAccess", "AmazonEC2FullAccess", "AdministratorAccess"],
    "ALLOWS_RESOURCE_EXPOSURE": ["AmazonEC2FullAccess", "AdministratorAccess"],
    "ALLOWS_FULL_ADMIN": ["AdministratorAccess"],
    "ALLOWS_PRIVILEGE_PASSING": ["AdministratorAccess"]
}
