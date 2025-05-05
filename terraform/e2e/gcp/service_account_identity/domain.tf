resource "google_service_account" "service_accounts" {
  for_each     = toset(var.ROLE_NAMES)

  # Modify account_id to comply with GCP requirements - must start with letter, use only lowercase, numbers, hyphens
  # 6-30 chars total, so we'll use a shorter format with just "id" plus role number
  # service account id, e.g., OWNER-55531-role1@cnapp-445301.iam.gserviceaccount.com
  account_id   = "${random_id.resource_prefix.hex}-${each.value}"
  # service account name, e.g., OWNER-12345678-role1
  display_name = "${random_id.resource_prefix.hex}-${each.value}"
  description  = "Service account for ${each.value} (Owner: ${var.OWNER})"

  # Add labels for tracking - Google doesn't support direct Owner labels, but we can include it in description
  project      = var.PROJECT_ID

  # Add explicit timeouts to handle eventual consistency issues
  timeouts {
    create = "10m"
  }
}

resource "google_project_iam_member" "role1_editor" {
  project = var.PROJECT_ID
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.service_accounts["role1"].email}"
}

# IAM roles equivalent to AWS AmazonS3FullAccess (roles 2)
resource "google_project_iam_member" "role2_storage_admin" {
  project = var.PROJECT_ID
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.service_accounts["role2"].email}"
}

# IAM roles equivalent to AWS AmazonS3ReadOnlyAccess (roles 3)
resource "google_project_iam_member" "role3_storage_viewer" {
  project = var.PROJECT_ID
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.service_accounts["role3"].email}"
}

# IAM roles equivalent to AWS SecretsManagerReadWrite (roles 4)
resource "google_project_iam_member" "role4_secret_manager_admin" {
  project = var.PROJECT_ID
  role    = "roles/secretmanager.admin"
  member  = "serviceAccount:${google_service_account.service_accounts["role4"].email}"
}

# IAM roles equivalent to AWS AmazonEC2FullAccess (roles 5)
resource "google_project_iam_member" "role5_compute_admin" {
  project = var.PROJECT_ID
  role    = "roles/compute.admin"
  member  = "serviceAccount:${google_service_account.service_accounts["role5"].email}"
}

# IAM roles equivalent to AWS AWSLambda_FullAccess (roles 6)
resource "google_project_iam_member" "role6_functions_admin" {
  project = var.PROJECT_ID
  role    = "roles/cloudfunctions.admin"
  member  = "serviceAccount:${google_service_account.service_accounts["role6"].email}"
}

# IAM roles equivalent to AWS AdministratorAccess (roles 7)
resource "google_project_iam_member" "role7_project_owner" {
  project = var.PROJECT_ID
  role    = "roles/owner"
  member  = "serviceAccount:${google_service_account.service_accounts["role7"].email}"
}

# GCP doesn't support tags directly on service accounts the same way as AWS
# Instead, use the description or specific IAM conditions if additional tagging is needed
