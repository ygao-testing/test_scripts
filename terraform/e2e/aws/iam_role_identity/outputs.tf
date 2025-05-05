output "iam_role_names" {
  value = [for r in aws_iam_role.roles : r.name]
}

# Define a map of policies and the roles assigned to each
locals {
  iam_policies_to_roles = {
    "IAMFullAccess"         = ["role1", "role2"]
    "AmazonS3FullAccess"    = ["role3", "role4"]
    "AmazonS3ReadOnlyAccess" = ["role5", "role6"]
    "SecretsManagerReadWrite" = ["role7", "role8"]
    "AmazonEC2FullAccess"   = ["role9", "role10"]
    "AWSLambda_FullAccess"  = ["role11", "role12"]
    "AdministratorAccess"   = ["role13", "role14"]
  }
}

# Output IAM roles by policy
output "iam_roles_by_policy" {
  value = {
    for policy, roles in local.iam_policies_to_roles : policy => [
      for role in roles : {
        name = aws_iam_role.roles[role].name
        arn  = aws_iam_role.roles[role].arn
      }
    ]
  }
}

output "lacework_expected_compliance" {
  value = {
    iam-role = {
      "lacework-global-486" = {
        compliant = [
          aws_iam_role.roles["role1"].arn,
          aws_iam_role.roles["role2"].arn,
          aws_iam_role.roles["role3"].arn,
          aws_iam_role.roles["role4"].arn,
          aws_iam_role.roles["role5"].arn,
          aws_iam_role.roles["role6"].arn,
          aws_iam_role.roles["role7"].arn,
          aws_iam_role.roles["role8"].arn,
          aws_iam_role.roles["role9"].arn,
          aws_iam_role.roles["role10"].arn,
          aws_iam_role.roles["role11"].arn,
          aws_iam_role.roles["role12"].arn
        ]
        non_compliant = [
          aws_iam_role.roles["role13"].arn,
          aws_iam_role.roles["role14"].arn
        ]
      }
    }
  }
}
