resource "aws_iam_group" "groups" {
  for_each = toset(var.GROUP_NAMES)

  name = "${random_id.resource_prefix.hex}${var.GROUP_PREFIX}${each.value}"
}

# IAMFullAccess
resource "aws_iam_group_policy_attachment" "group1_policy_attachment" {
  group      = aws_iam_group.groups["group1"].name
  policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"
}

resource "aws_iam_group_policy_attachment" "group2_policy_attachment" {
  group      = aws_iam_group.groups["group2"].name
  policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"
}

# AmazonS3FullAccess
resource "aws_iam_group_policy_attachment" "group3_policy_attachment" {
  group      = aws_iam_group.groups["group3"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_group_policy_attachment" "group4_policy_attachment" {
  group      = aws_iam_group.groups["group4"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

# AmazonS3ReadOnlyAccess
resource "aws_iam_group_policy_attachment" "group5_policy_attachment" {
  group      = aws_iam_group.groups["group5"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_group_policy_attachment" "group6_policy_attachment" {
  group      = aws_iam_group.groups["group6"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# SecretsManagerReadWrite
resource "aws_iam_group_policy_attachment" "group7_policy_attachment" {
  group      = aws_iam_group.groups["group7"].name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
}

resource "aws_iam_group_policy_attachment" "group8_policy_attachment" {
  group      = aws_iam_group.groups["group8"].name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
}

# AmazonEC2FullAccess
resource "aws_iam_group_policy_attachment" "group9_policy_attachment" {
  group      = aws_iam_group.groups["group9"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_iam_group_policy_attachment" "group10_policy_attachment" {
  group      = aws_iam_group.groups["group10"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

# AWSLambda_FullAccess
resource "aws_iam_group_policy_attachment" "group11_policy_attachment" {
  group      = aws_iam_group.groups["group11"].name
  policy_arn = "arn:aws:iam::aws:policy/AWSLambda_FullAccess"
}

resource "aws_iam_group_policy_attachment" "group12_policy_attachment" {
  group      = aws_iam_group.groups["group12"].name
  policy_arn = "arn:aws:iam::aws:policy/AWSLambda_FullAccess"
}

# AdministratorAccess
resource "aws_iam_group_policy_attachment" "group13_policy_attachment" {
  group      = aws_iam_group.groups["group13"].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_group_policy_attachment" "group14_policy_attachment" {
  group      = aws_iam_group.groups["group14"].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
