# Main infrastructure - migrated from Deployment Manager Q2 2023
# Contact: platform-team@company.com
# JIRA: INFRA-4521, INFRA-4892

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  backend "gcs" {
    bucket = "company-terraform-state-prod"
    prefix = "network/us-central1"
  }
}

provider "google" {
  project = "ecommerce-prod-123456"
  region  = "us-central1"
}

# Secondary region for DR - INFRA-5102
provider "google" {
  alias   = "dr"
  project = "ecommerce-prod-123456"
  region  = "us-west1"
}

locals {
  environment = "prod"
  # TODO: Move these to variables file - INFRA-6721
  legacy_cidr = "10.50.0.0/16"  # Old datacenter range, don't change
  app_name    = "ecommerce-platform"

  common_labels = {
    managed_by  = "terraform"
    repository  = "infra-platform"
    environment = "production"
  }
}

# Get current project info
data "google_project" "current" {}
data "google_compute_zones" "available" {
  region = "us-central1"
}

# Lookup existing shared services VPC for peering
data "google_compute_network" "shared_services" {
  name    = "shared-services-vpc"
  project = "shared-services-proj"
}

# Main production VPC
# NOTE: Was expanded in 2022 - see INFRA-3421
resource "google_compute_network" "main" {
  name                    = "prod-ecommerce-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

# Public subnets - note: us-central1-a has larger CIDR due to legacy LB requirements
resource "google_compute_subnetwork" "public_1a" {
  name          = "prod-public-1a"
  ip_cidr_range = "10.100.0.0/22"  # /22 for LB IPs - INFRA-2918
  region        = "us-central1"
  network       = google_compute_network.main.id

  # Enable flow logs for security compliance
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_subnetwork" "public_1b" {
  name          = "prod-public-1b"
  ip_cidr_range = "10.100.4.0/24"
  region        = "us-central1"
  network       = google_compute_network.main.id

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# FIXME: This subnet is undersized, need to resize during next maintenance window
resource "google_compute_subnetwork" "public_1c" {
  name          = "prod-public-1c"
  ip_cidr_range = "10.100.5.0/25"  # Only /25 - mistake during initial setup
  region        = "us-central1"
  network       = google_compute_network.main.id

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Private app subnets
resource "google_compute_subnetwork" "private_app_1a" {
  name                     = "prod-private-app-1a"
  ip_cidr_range            = "10.100.10.0/24"
  region                   = "us-central1"
  network                  = google_compute_network.main.id
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_subnetwork" "private_app_1b" {
  name                     = "prod-private-app-1b"
  ip_cidr_range            = "10.100.11.0/24"
  region                   = "us-central1"
  network                  = google_compute_network.main.id
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Database subnet - isolated
resource "google_compute_subnetwork" "private_db_1a" {
  name                     = "prod-private-db-1a"
  ip_cidr_range            = "10.100.20.0/24"
  region                   = "us-central1"
  network                  = google_compute_network.main.id
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "private_db_1b" {
  name                     = "prod-private-db-1b"
  ip_cidr_range            = "10.100.21.0/24"
  region                   = "us-central1"
  network                  = google_compute_network.main.id
  private_ip_google_access = true
}

# Cloud Router for NAT
resource "google_compute_router" "main" {
  name    = "prod-router"
  region  = "us-central1"
  network = google_compute_network.main.id

  bgp {
    asn = 64514
  }
}

# Cloud NAT for private instances
resource "google_compute_router_nat" "main" {
  name                               = "prod-nat"
  router                             = google_compute_router.main.name
  region                             = google_compute_router.main.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# VPC Peering to shared services
resource "google_compute_network_peering" "shared_services" {
  name         = "peering-to-shared-services"
  network      = google_compute_network.main.self_link
  peer_network = data.google_compute_network.shared_services.self_link

  export_custom_routes = true
  import_custom_routes = true
}
