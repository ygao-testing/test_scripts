output "iam_user_arn" {
  value = aws_iam_user.user.arn
}

output "s3_bucket_arn" {
  value = aws_s3_bucket.s3_bucket.arn
}
output "lacework_expected_compliance" {
  value = {
    iam-user = {
       "lacework-global-42" = {
        compliant     = [aws_iam_user.user.arn]
        non_compliant = []
      }
      "lacework-global-44" = {
        compliant     = []
        non_compliant = [aws_iam_user.user.arn]
      }
      "lacework-global-45" = {
        compliant     = [aws_iam_user.user.arn]
        non_compliant = []
      }
    }
  }
}
