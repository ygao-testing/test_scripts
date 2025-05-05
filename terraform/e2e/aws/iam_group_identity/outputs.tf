output "iam_group_names" {
  value = [for g in aws_iam_group.groups : g.name]
}

# Define a map of policies and the groups assigned to each
locals {
  iam_policies_to_groups = {
    "IAMFullAccess"         = ["group1", "group2"]
    "AmazonS3FullAccess"    = ["group3", "group4"]
    "AmazonS3ReadOnlyAccess" = ["group5", "group6"]
    "SecretsManagerReadWrite" = ["group7", "group8"]
    "AmazonEC2FullAccess"   = ["group9", "group10"]
    "AWSLambda_FullAccess"  = ["group11", "group12"]
    "AdministratorAccess"   = ["group13", "group14"]
  }
}

# Output IAM groups by policy
output "iam_groups_by_policy" {
  value = {
    for policy, groups in local.iam_policies_to_groups : policy => [
      for group in groups : {
        name = aws_iam_group.groups[group].name
        arn  = aws_iam_group.groups[group].arn
      }
    ]
  }
}
output "lacework_expected_compliance" {
  value = {
    iam-group = {
      "lacework-global-485" = {
        compliant = [
          aws_iam_group.groups["group1"].arn,
          aws_iam_group.groups["group2"].arn,
          aws_iam_group.groups["group3"].arn,
          aws_iam_group.groups["group4"].arn,
          aws_iam_group.groups["group5"].arn,
          aws_iam_group.groups["group6"].arn,
          aws_iam_group.groups["group7"].arn,
          aws_iam_group.groups["group8"].arn,
          aws_iam_group.groups["group9"].arn,
          aws_iam_group.groups["group10"].arn,
          aws_iam_group.groups["group11"].arn,
          aws_iam_group.groups["group12"].arn
        ]
        non_compliant = [
          aws_iam_group.groups["group13"].arn,
          aws_iam_group.groups["group14"].arn
        ]
      }
    }
  }
}
