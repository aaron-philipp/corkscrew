# Compute instances - various teams and purposes
# Managed by platform-team@company.com

# Bastion host for emergency access
# TODO: Replace with IAP direct access - INFRA-7821
resource "google_compute_instance" "bastion" {
  name         = "prod-bastion"
  machine_type = "e2-micro"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 20
      type  = "pd-ssd"
    }
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.public_1a.name
    access_config {
      // Ephemeral public IP
    }
  }

  service_account {
    email  = google_service_account.api_server.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  labels = merge(local.common_labels, {
    owner       = "platform-team"
    purpose     = "emergency-access"
    auto_stop   = "false"
  })

  tags = ["bastion", "allow-ssh"]

  lifecycle {
    ignore_changes = [boot_disk[0].initialize_params[0].image]
  }
}

# Legacy jump box - DO NOT DELETE - used by contractor VPN
# Ticket: INFRA-1234 - will decommission after contract ends Dec 2024
resource "google_compute_instance" "old_jumpbox" {
  name         = "legacy-jumpbox-dont-delete"
  machine_type = "e2-small"  # Legacy sizing
  zone         = "us-central1-b"

  boot_disk {
    initialize_params {
      image = "centos-cloud/centos-7"  # Old CentOS 7
      size  = 30
    }
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.public_1b.name
    access_config {}
  }

  labels = {
    owner              = "john-smith"
    decommission_date  = "2024-12-31"
    ticket_ref         = "infra-1234"
  }

  tags = ["legacy-dc-access", "allow-ssh"]
}

# API servers - mixed instance types from different scaling events
resource "google_compute_instance" "api_primary" {
  name         = "prod-api-1"
  machine_type = "n2-standard-4"  # Upgraded INFRA-5521
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 50
      type  = "pd-ssd"
    }
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.private_app_1a.name
  }

  service_account {
    email  = google_service_account.api_server.email
    scopes = ["cloud-platform"]
  }

  labels = merge(local.common_labels, {
    service     = "api-gateway"
    owner       = "api-team"
    cost_center = "cc-4521"
  })

  tags = ["api-tier", "allow-health-check"]

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_instance" "api_secondary" {
  name         = "prod-api-2"
  machine_type = "n2-standard-2"  # Smaller, added during incident
  zone         = "us-central1-b"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 50
      type  = "pd-ssd"
    }
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.private_app_1b.name
  }

  service_account {
    email  = google_service_account.api_server.email
    scopes = ["cloud-platform"]
  }

  labels = merge(local.common_labels, {
    service      = "api-gateway"
    owner        = "api-team"
    added_during = "incident-2023-11-15"  # Added during Black Friday incident
  })

  tags = ["api-tier", "allow-health-check"]
}

# Worker instances - using older N1 type (committed use discount)
resource "google_compute_instance" "worker_1" {
  name         = "prod-worker-batch-01"
  machine_type = "n1-standard-2"  # CUD, expires 2025-06
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 100
    }
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.private_app_1a.name
  }

  service_account {
    email  = google_service_account.batch_worker.email
    scopes = ["cloud-platform"]
  }

  labels = {
    service          = "batch-processor"
    cud_commitment   = "cud-0abc123"
    cud_expires      = "2025-06-30"
  }

  tags = ["worker-tier"]
}

# Instance template for auto-scaling group
resource "google_compute_instance_template" "api" {
  name_prefix  = "api-template-"
  machine_type = "n2-standard-2"
  region       = "us-central1"

  disk {
    source_image = "debian-cloud/debian-11"
    auto_delete  = true
    boot         = true
    disk_type    = "pd-ssd"
    disk_size_gb = 50
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.private_app_1a.name
  }

  service_account {
    email  = google_service_account.api_server.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  labels = merge(local.common_labels, {
    service = "api-gateway"
    owner   = "api-team"
  })

  tags = ["api-tier", "allow-health-check"]

  lifecycle {
    create_before_destroy = true
  }
}
