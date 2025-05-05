# IAM Policy 1
resource "aws_iam_policy" "gha_ingestion_policy_1" {
  name        = "${random_id.resource_prefix.hex}-gha_ingestion_list_s3_policy_1"
  description = "Policy 1: Allow listing all S3 buckets"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:ListAllMyBuckets"
        Resource = "*"
      }
    ]
  })
}

# IAM Policy 2
resource "aws_iam_policy" "gha_ingestion_policy_2" {
  name        = "${random_id.resource_prefix.hex}-gha_ingestion_list_s3_policy_2"
  description = "Policy 2: Allow listing all S3 buckets"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:ListAllMyBuckets"
        Resource = "*"
      }
    ]
  })
}
