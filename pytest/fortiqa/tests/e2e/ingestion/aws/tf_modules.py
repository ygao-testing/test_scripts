# e2e_resource_inventory_tf_modules = [
#     "inventory"
# ]
e2e_aws_tf_modules = [
    "ec2_lateral_ssh_movement",
    "ec2_open_to_public",
    "ec2_open_ssh",
    "ec2_internet_expose_with_critical_active_pacakge",
    "inventory",
    "iam_user_with_specific_s3_access",
    "iam_user_with_s3_full_acess",
    "iam_user_identity",
    "iam_role_identity",
    "iam_group_identity"
]

iam_user_and_accessible_s3_bucket_tf_modules = [
    "iam_user_with_specific_s3_access",
    "iam_user_with_s3_full_acess",
]
