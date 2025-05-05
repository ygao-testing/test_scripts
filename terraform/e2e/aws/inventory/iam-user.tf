resource "aws_iam_user" "gha_ingestion_user1" {
  name = "${random_id.resource_prefix.hex}-gha_ingestion_user1"
}
resource "aws_iam_user" "gha_ingestion_user2" {
  name = "${random_id.resource_prefix.hex}-gha_ingestion_user2"
}
# IAM User 1 - Has Two Access Keys
resource "aws_iam_user" "user_with_2_access_keys_user1" {
  name = "${random_id.resource_prefix.hex}-with-2-access-keys-user1"
}

resource "aws_iam_access_key" "user_with_2_access_keys_user1_key1" {
  user = aws_iam_user.user_with_2_access_keys_user1.name
}

resource "aws_iam_access_key" "user_with_2_access_keys_user1_key2" {
  user = aws_iam_user.user_with_2_access_keys_user1.name
}

# IAM User 2 - Has Two Access Keys
resource "aws_iam_user" "user_with_2_access_keys_user2" {
  name = "${random_id.resource_prefix.hex}-with-2-access-keys-user2"
}

resource "aws_iam_access_key" "user_with_2_access_keys_user2_key1" {
  user = aws_iam_user.user_with_2_access_keys_user2.name
}

resource "aws_iam_access_key" "user_with_2_access_keys_user2_key2" {
  user = aws_iam_user.user_with_2_access_keys_user2.name
}
