
resource "aws_iam_user" "users" {
  for_each = toset(var.USER_NAME)
  name     = "${random_id.resource_prefix.hex}${var.USER_PREFIX}${each.value}"
  path     = "/"
}

# IAMFullAccess - First user with console, second with access key
resource "aws_iam_user_policy_attachment" "user1_policy_attachment" {
  user       = aws_iam_user.users["user1"].name
  policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"
}
resource "aws_iam_user_login_profile" "user1_console_access" {
  user = aws_iam_user.users["user1"].name
}

resource "aws_iam_user_policy_attachment" "user2_policy_attachment" {
  user       = aws_iam_user.users["user2"].name
  policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"
}
resource "aws_iam_access_key" "user2_access_key" {
  user = aws_iam_user.users["user2"].name
}

# AmazonS3FullAccess - First user with console, second with access key
resource "aws_iam_user_policy_attachment" "user3_policy_attachment" {
  user       = aws_iam_user.users["user3"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}
resource "aws_iam_user_login_profile" "user3_console_access" {
  user = aws_iam_user.users["user3"].name
}

resource "aws_iam_user_policy_attachment" "user4_policy_attachment" {
  user       = aws_iam_user.users["user4"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}
resource "aws_iam_access_key" "user4_access_key" {
  user = aws_iam_user.users["user4"].name
}

# AmazonS3ReadOnlyAccess - First user with console, second with access key
resource "aws_iam_user_policy_attachment" "user5_policy_attachment" {
  user       = aws_iam_user.users["user5"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}
resource "aws_iam_user_login_profile" "user5_console_access" {
  user = aws_iam_user.users["user5"].name
}

resource "aws_iam_user_policy_attachment" "user6_policy_attachment" {
  user       = aws_iam_user.users["user6"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}
resource "aws_iam_access_key" "user6_access_key" {
  user = aws_iam_user.users["user6"].name
}

# SecretsManagerReadWrite - First user with console, second with access key
resource "aws_iam_user_policy_attachment" "user7_policy_attachment" {
  user       = aws_iam_user.users["user7"].name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
}
resource "aws_iam_user_login_profile" "user7_console_access" {
  user = aws_iam_user.users["user7"].name
}

resource "aws_iam_user_policy_attachment" "user8_policy_attachment" {
  user       = aws_iam_user.users["user8"].name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
}
resource "aws_iam_access_key" "user8_access_key" {
  user = aws_iam_user.users["user8"].name
}

# AmazonEC2FullAccess - First user with console, second with access key
resource "aws_iam_user_policy_attachment" "user9_policy_attachment" {
  user       = aws_iam_user.users["user9"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}
resource "aws_iam_user_login_profile" "user9_console_access" {
  user = aws_iam_user.users["user9"].name
}

resource "aws_iam_user_policy_attachment" "user10_policy_attachment" {
  user       = aws_iam_user.users["user10"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}
resource "aws_iam_access_key" "user10_access_key" {
  user = aws_iam_user.users["user10"].name
}

# AWSLambda_FullAccess - First user with console, second with access key
resource "aws_iam_user_policy_attachment" "user11_policy_attachment" {
  user       = aws_iam_user.users["user11"].name
  policy_arn = "arn:aws:iam::aws:policy/AWSLambda_FullAccess"
}
resource "aws_iam_user_login_profile" "user11_console_access" {
  user = aws_iam_user.users["user11"].name
}

resource "aws_iam_user_policy_attachment" "user12_policy_attachment" {
  user       = aws_iam_user.users["user12"].name
  policy_arn = "arn:aws:iam::aws:policy/AWSLambda_FullAccess"
}
resource "aws_iam_access_key" "user12_access_key" {
  user = aws_iam_user.users["user12"].name
}
# AdministratorAccess - First user with console, second with access key
resource "aws_iam_user_policy_attachment" "user13_policy_attachment" {
  user       = aws_iam_user.users["user13"].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user_login_profile" "user13_console_access" {
  user = aws_iam_user.users["user13"].name
}

resource "aws_iam_user_policy_attachment" "user14_policy_attachment" {
  user       = aws_iam_user.users["user14"].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_access_key" "user14_access_key" {
  user = aws_iam_user.users["user14"].name
}
