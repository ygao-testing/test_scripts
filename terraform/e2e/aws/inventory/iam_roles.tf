# IAM Role 1
resource "aws_iam_role" "gha_ingestion_role_1" {
  name = "${random_id.resource_prefix.hex}-gha_ingestion_ec2_role_1"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# IAM Role 2
resource "aws_iam_role" "gha_ingestion_role_2" {
  name = "${random_id.resource_prefix.hex}-gha_ingestion_ec2_role_2"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Attach Policy 1 to Role 1
resource "aws_iam_role_policy_attachment" "gha_ingestion_attachment_1" {
  role       = aws_iam_role.gha_ingestion_role_1.name
  policy_arn = aws_iam_policy.gha_ingestion_policy_1.arn
}

# Attach Policy 2 to Role 2
resource "aws_iam_role_policy_attachment" "gha_ingestion_attachment_2" {
  role       = aws_iam_role.gha_ingestion_role_2.name
  policy_arn = aws_iam_policy.gha_ingestion_policy_2.arn
}
