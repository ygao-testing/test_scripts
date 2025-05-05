output "service_account_emails" {
  description = "Map of service account names to their emails"
  value = {
    for name, sa in google_service_account.service_accounts : name => sa.email
  }
}

output "service_account_ids" {
  description = "Map of service account names to their unique IDs"
  value = {
    for name, sa in google_service_account.service_accounts : name => sa.id
  }
}

output "service_account_names" {
  description = "Map of service account names to their display names"
  value = {
    for name, sa in google_service_account.service_accounts : name => sa.display_name
  }
}

output "resource_prefix" {
  description = "Random prefix used for all resources"
  value       = random_id.resource_prefix.hex
}
