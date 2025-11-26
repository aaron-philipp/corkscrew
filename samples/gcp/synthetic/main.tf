# Synthetic/Honeypot Infrastructure Example (GCP)
# This file demonstrates patterns typical of auto-generated or honeypot infrastructure

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# VPC with simple naming - no context
resource "google_compute_network" "main" {
  name                    = "production-vpc"
  auto_create_subnetworks = false

  # No labels - honeypots often skip metadata
}

# Perfectly balanced subnets - identical sizing, sequential CIDRs
resource "google_compute_subnetwork" "public-1" {
  name          = "public-subnet-1"
  ip_cidr_range = "10.0.1.0/24"
  region        = "us-central1"
  network       = google_compute_network.main.id
}

resource "google_compute_subnetwork" "public-2" {
  name          = "public-subnet-2"
  ip_cidr_range = "10.0.2.0/24"
  region        = "us-central1"
  network       = google_compute_network.main.id
}

resource "google_compute_subnetwork" "public-3" {
  name          = "public-subnet-3"
  ip_cidr_range = "10.0.3.0/24"
  region        = "us-central1"
  network       = google_compute_network.main.id
}

resource "google_compute_subnetwork" "private-1" {
  name          = "private-subnet-1"
  ip_cidr_range = "10.0.4.0/24"
  region        = "us-central1"
  network       = google_compute_network.main.id
}

resource "google_compute_subnetwork" "private-2" {
  name          = "private-subnet-2"
  ip_cidr_range = "10.0.5.0/24"
  region        = "us-central1"
  network       = google_compute_network.main.id
}

resource "google_compute_subnetwork" "private-3" {
  name          = "private-subnet-3"
  ip_cidr_range = "10.0.6.0/24"
  region        = "us-central1"
  network       = google_compute_network.main.id
}

# Identical firewall rules - too clean, no accumulated rules
resource "google_compute_firewall" "web-server" {
  name    = "web-server-fw"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["web-server"]
}

resource "google_compute_firewall" "app-server" {
  name    = "app-server-fw"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["8080", "8443"]
  }

  source_ranges = ["10.0.0.0/16"]
  target_tags   = ["app-server"]
}

resource "google_compute_firewall" "db-server" {
  name    = "db-server-fw"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["3306", "5432"]
  }

  source_ranges = ["10.0.0.0/16"]
  target_tags   = ["db-server"]
}

# Formulaic instance naming - web-server-01, web-server-02, etc.
# All identical machine types - no variation
resource "google_compute_instance" "web-server-01" {
  name         = "web-server-01"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.public-1.name
    access_config {}
  }

  tags = ["web-server"]
}

resource "google_compute_instance" "web-server-02" {
  name         = "web-server-02"
  machine_type = "e2-medium"
  zone         = "us-central1-b"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.public-2.name
    access_config {}
  }

  tags = ["web-server"]
}

resource "google_compute_instance" "web-server-03" {
  name         = "web-server-03"
  machine_type = "e2-medium"
  zone         = "us-central1-c"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.public-3.name
    access_config {}
  }

  tags = ["web-server"]
}

resource "google_compute_instance" "app-server-01" {
  name         = "app-server-01"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.private-1.name
  }

  tags = ["app-server"]
}

resource "google_compute_instance" "app-server-02" {
  name         = "app-server-02"
  machine_type = "e2-medium"
  zone         = "us-central1-b"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.private-2.name
  }

  tags = ["app-server"]
}

resource "google_compute_instance" "app-server-03" {
  name         = "app-server-03"
  machine_type = "e2-medium"
  zone         = "us-central1-c"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.private-3.name
  }

  tags = ["app-server"]
}

resource "google_compute_instance" "db-server-01" {
  name         = "db-server-01"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.private-1.name
  }

  tags = ["db-server"]
}

resource "google_compute_instance" "db-server-02" {
  name         = "db-server-02"
  machine_type = "e2-medium"
  zone         = "us-central1-b"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.main.name
    subnetwork = google_compute_subnetwork.private-2.name
  }

  tags = ["db-server"]
}
