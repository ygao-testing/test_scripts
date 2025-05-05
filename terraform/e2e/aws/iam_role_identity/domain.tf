resource "aws_iam_role" "roles" {
  for_each = toset(var.ROLE_NAMES)

  name               = "${random_id.resource_prefix.hex}${var.ROLE_PREFIX}${each.value}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# IAMFullAccess
resource "aws_iam_role_policy_attachment" "role1_policy_attachment" {
  role       = aws_iam_role.roles["role1"].name
  policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"
}

resource "aws_iam_role_policy_attachment" "role2_policy_attachment" {
  role       = aws_iam_role.roles["role2"].name
  policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"
}

# AmazonS3FullAccess
resource "aws_iam_role_policy_attachment" "role3_policy_attachment" {
  role       = aws_iam_role.roles["role3"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_role_policy_attachment" "role4_policy_attachment" {
  role       = aws_iam_role.roles["role4"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

# AmazonS3ReadOnlyAccess
resource "aws_iam_role_policy_attachment" "role5_policy_attachment" {
  role       = aws_iam_role.roles["role5"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "role6_policy_attachment" {
  role       = aws_iam_role.roles["role6"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# SecretsManagerReadWrite
resource "aws_iam_role_policy_attachment" "role7_policy_attachment" {
  role       = aws_iam_role.roles["role7"].name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
}

resource "aws_iam_role_policy_attachment" "role8_policy_attachment" {
  role       = aws_iam_role.roles["role8"].name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
}

# AmazonEC2FullAccess
resource "aws_iam_role_policy_attachment" "role9_policy_attachment" {
  role       = aws_iam_role.roles["role9"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

resource "aws_iam_role_policy_attachment" "role10_policy_attachment" {
  role       = aws_iam_role.roles["role10"].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

# AWSLambda_FullAccess
resource "aws_iam_role_policy_attachment" "role11_policy_attachment" {
  role       = aws_iam_role.roles["role11"].name
  policy_arn = "arn:aws:iam::aws:policy/AWSLambda_FullAccess"
}

resource "aws_iam_role_policy_attachment" "role12_policy_attachment" {
  role       = aws_iam_role.roles["role12"].name
  policy_arn = "arn:aws:iam::aws:policy/AWSLambda_FullAccess"
}

# AdministratorAccess
resource "aws_iam_role_policy_attachment" "role13_policy_attachment" {
  role       = aws_iam_role.roles["role13"].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy_attachment" "role14_policy_attachment" {
  role       = aws_iam_role.roles["role14"].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
