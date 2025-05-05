resource "aws_iam_role" "roles" {
  for_each = toset(var.ROLE_NAME)
  name     = "${var.ROLE_PREFIX}${each.value}"
  path     = "/"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "role1_policy_attachment" {
  role       = aws_iam_role.roles["role1"].name
  policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"  # Default IAM Full Access policy
}

resource "aws_iam_role_policy_attachment" "role2_policy_attachment" {
  role       = aws_iam_role.roles["role2"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"  # Default S3 Full Access policy
}

resource "aws_iam_role_policy_attachment" "role3_policy_attachment" {
  role       = aws_iam_role.roles["role3"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"  # Default S3 Read-Only policy
}

resource "aws_iam_role_policy_attachment" "role4_policy_attachment" {
  role       = aws_iam_role.roles["role4"].name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"  # Default Secrets Manager read/write policy
}
