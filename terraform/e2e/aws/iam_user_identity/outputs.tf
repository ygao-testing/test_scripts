output "iam_user_names" {
  value = [for u in aws_iam_user.users : u.name]
}
# Define a map of policies and the users assigned to each
locals {
  iam_policies_to_users = {
    "IAMFullAccess" = ["user1", "user2"]
    "AmazonS3FullAccess" = ["user3", "user4"]
    "AmazonS3ReadOnlyAccess" = ["user5", "user6"]
    "SecretsManagerReadWrite" = ["user7","user8"]
    "AmazonEC2FullAccess" = ["user9", "user10"]
    "AWSLambda_FullAccess" =  ["user11","user12"]
    "AdministratorAccess" = ["user13","user14"]
  }
  user_access = {
     "ConsoleAccess" = ["user1", "user3","user5","user7","user9","user11","user13"]
    "Accesskey" = ["user2", "user4","user6","user8","user10","user12","user14"]
  }
}
# Output the IAM users by policy and access
output "iam_users_by_policy" {
  value = {
    for policy, users in local.iam_policies_to_users : policy => [
      for user in users : {
        name = aws_iam_user.users[user].name
        arn  = aws_iam_user.users[user].arn
      }
    ]
  }
}
# Output the IAM users by access
output "iam_users_by_access" {
  value = {
    for access, users in local.user_access : access => [
      for user in users : {
        name = aws_iam_user.users[user].name
        arn  = aws_iam_user.users[user].arn
      }
    ]
  }
}
output "lacework_expected_compliance" {
  value = {
    iam-user = {
      "lacework-global-42" = {
        compliant     = [for u in aws_iam_user.users : u.arn]
        non_compliant = []
      }
      "lacework-global-44" = {
        compliant     = []
        non_compliant = [for u in aws_iam_user.users : u.arn]
      }
      "lacework-global-45" = {
        compliant     = [for u in aws_iam_user.users : u.arn if !(u.name == aws_iam_user.users["user13"].name || u.name == aws_iam_user.users["user14"].name)]
        non_compliant = [aws_iam_user.users["user13"].arn, aws_iam_user.users["user14"].arn]
      }
    }
  }
}
