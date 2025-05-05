resource "aws_iam_user""user"{
  name = "${random_id.resource_prefix.hex}-user"
}

resource "aws_iam_user_policy_attachment" "user_policy_attachment" {
  user       = aws_iam_user.user.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"  # Default S3 Full Access policy
}

resource "aws_s3_bucket" "s3_bucket" {
  bucket = "${lower(random_id.resource_prefix.hex)}-s3"
  acl    = "private"
}
