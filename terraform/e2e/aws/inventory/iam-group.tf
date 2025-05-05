
resource "aws_iam_group" "gha_ingestion_group1" {
  name = "${random_id.resource_prefix.hex}-gha_ingestion_group1"
}
resource "aws_iam_group" "gha_ingestion_group2" {
  name = "${random_id.resource_prefix.hex}-gha_ingestion_group2"
}
