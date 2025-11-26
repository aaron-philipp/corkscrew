# IAM configuration - managed by security team
# Contact: sec-team@company.com

# Service account for API servers
resource "google_service_account" "api_server" {
  account_id   = "api-server-sa"
  display_name = "API Server Service Account"
  description  = "SA for API server instances - INFRA-5521"
}

# Service account for batch workers
resource "google_service_account" "batch_worker" {
  account_id   = "batch-worker-sa"
  display_name = "Batch Worker Service Account"
  description  = "SA for batch processing workers"
}

# Service account for CI/CD - used by GitHub Actions
resource "google_service_account" "cicd" {
  account_id   = "cicd-deploy-sa"
  display_name = "CI/CD Deployment Service Account"
  description  = "Used by GitHub Actions for deployments"
}

# API server needs to read from GCS and publish to Pub/Sub
resource "google_project_iam_member" "api_storage" {
  project = data.google_project.current.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.api_server.email}"
}

resource "google_project_iam_member" "api_pubsub" {
  project = data.google_project.current.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.api_server.email}"
}

# Batch worker needs broader access for data processing
resource "google_project_iam_member" "batch_storage" {
  project = data.google_project.current.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.batch_worker.email}"
}

resource "google_project_iam_member" "batch_bigquery" {
  project = data.google_project.current.project_id
  role    = "roles/bigquery.dataEditor"
  member  = "serviceAccount:${google_service_account.batch_worker.email}"
}

# CI/CD needs to deploy to GKE and update Cloud Run
resource "google_project_iam_member" "cicd_gke" {
  project = data.google_project.current.project_id
  role    = "roles/container.developer"
  member  = "serviceAccount:${google_service_account.cicd.email}"
}

resource "google_project_iam_member" "cicd_run" {
  project = data.google_project.current.project_id
  role    = "roles/run.admin"
  member  = "serviceAccount:${google_service_account.cicd.email}"
}

resource "google_project_iam_member" "cicd_sa_user" {
  project = data.google_project.current.project_id
  role    = "roles/iam.serviceAccountUser"
  member  = "serviceAccount:${google_service_account.cicd.email}"
}

# Legacy service account - DO NOT DELETE - used by contractor integration
# Ticket: INFRA-1234 - will decommission after contract ends Dec 2024
resource "google_service_account" "legacy_contractor" {
  account_id   = "contractor-integration-sa"
  display_name = "Contractor Integration (Legacy)"
  description  = "LEGACY: Contractor VPN integration - decommission Dec 2024"
}

resource "google_project_iam_member" "legacy_storage" {
  project = data.google_project.current.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.legacy_contractor.email}"
}
