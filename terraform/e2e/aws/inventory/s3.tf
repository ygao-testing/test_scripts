resource "aws_s3_bucket" "s3_bucket" {
  bucket = "${random_id.s3_resource_prefix.hex}-for-inventory-bucket"

  tags = {
    Name = "${random_id.resource_prefix.hex}-for-inventory-bucket"
    Type = "s3-test"
  }
}

resource "aws_s3_bucket" "s3_bucket_bpa_disabled_versioning_enabled" {
  bucket = "${random_id.s3_resource_prefix.hex}-bpa-dis-versioning-enabled"

  tags = {
    Name = "${random_id.resource_prefix.hex}-bpa-dis-versioning-enabled"
    Type = "s3-test"
  }
}

resource "aws_s3_bucket_public_access_block" "bpa_disabled" {
  bucket = aws_s3_bucket.s3_bucket_bpa_disabled_versioning_enabled.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_versioning" "versioning_enabled" {
  bucket = aws_s3_bucket.s3_bucket_bpa_disabled_versioning_enabled.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "s3_bucket_deny_http" {
  bucket = "${random_id.s3_resource_prefix.hex}-deny-http"

  tags = {
    Name = "${random_id.resource_prefix.hex}-deny-http"
    Type = "s3-test"
  }
}

resource "aws_s3_bucket_policy" "deny_http_policy" {
  bucket = aws_s3_bucket.s3_bucket_deny_http.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "DenyUnEncryptedTransport",
        Effect = "Deny",
        Principal = "*",
        Action = "s3:*",
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.s3_bucket_deny_http.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.s3_bucket_deny_http.bucket}/*"
        ],
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket" "s3_bucket_get_public_bpa_disabled" {
  bucket = "${random_id.s3_resource_prefix.hex}-get-public-bpa-dis"

  tags = {
    Name = "${random_id.resource_prefix.hex}-get-public-bpa-dis"
    Type = "s3-test"
  }
}

resource "aws_s3_bucket_public_access_block" "bpa_disabled_get_public" {
  bucket = aws_s3_bucket.s3_bucket_get_public_bpa_disabled.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "get_object_public_policy" {
  bucket = aws_s3_bucket.s3_bucket_get_public_bpa_disabled.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AllowGlobalGet",
        Effect    = "Allow",
        Principal = "*",
        Action    = "s3:Get*",
        Resource  = [
          "arn:aws:s3:::${aws_s3_bucket.s3_bucket_get_public_bpa_disabled.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.s3_bucket_get_public_bpa_disabled.bucket}/*"
        ]
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.bpa_disabled_get_public]
}

resource "aws_s3_bucket" "s3_bucket_global_list_bpa_disabled" {
  bucket = "${random_id.s3_resource_prefix.hex}-global-list-bpa-dis"

  tags = {
    Name = "${random_id.resource_prefix.hex}-global-list-bpa-dis"
    Type = "s3-test"
  }
}

resource "aws_s3_bucket_public_access_block" "bpa_disabled_global_list" {
  bucket = aws_s3_bucket.s3_bucket_global_list_bpa_disabled.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "global_list_policy" {
  bucket = aws_s3_bucket.s3_bucket_global_list_bpa_disabled.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AllowGlobalListBucket",
        Effect    = "Allow",
        Principal = "*",
        Action    = "s3:List*",
        Resource  = [
          "arn:aws:s3:::${aws_s3_bucket.s3_bucket_global_list_bpa_disabled.bucket}",
          "arn:aws:s3:::${aws_s3_bucket.s3_bucket_global_list_bpa_disabled.bucket}/*"
        ]
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.bpa_disabled_global_list]
}
