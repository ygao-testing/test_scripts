resource "aws_iam_user" "users" {
  for_each = toset(var.USER_NAME)
  name     = "${var.USER_PREFIX}${each.value}"
  path     = "/"
}

resource "aws_iam_user_policy_attachment" "user1_policy_attachment" {
  user       = aws_iam_user.users["user1"].name
  policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"  # Default IAM Full Access policy
}

resource "aws_iam_user_policy_attachment" "user2_policy_attachment" {
  user       = aws_iam_user.users["user2"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"  # Default S3 Full Access policy
}

resource "aws_iam_user_policy_attachment" "user3_policy_attachment" {
  user       = aws_iam_user.users["user3"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"  # Default S3 Read-Only policy
}

resource "aws_iam_user_policy_attachment" "user4_policy_attachment" {
  user       = aws_iam_user.users["user4"].name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"  # Default Secrets Manager read/write policy
}

resource "aws_iam_user_login_profile" "user1_console_access" {
  user = aws_iam_user.users["user1"].name
}

resource "aws_iam_user_login_profile" "user2_console_access" {
  user = aws_iam_user.users["user2"].name
}

resource "aws_iam_user_login_profile" "user3_console_access" {
  user = aws_iam_user.users["user3"].name
}

resource "aws_iam_user_login_profile" "user4_console_access" {
  user = aws_iam_user.users["user4"].name
}
