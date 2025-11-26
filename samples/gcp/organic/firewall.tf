# Firewall rules - accumulated over time with various requirements
# Security team: sec-team@company.com

# Allow IAP for SSH - SEC-2103
resource "google_compute_firewall" "allow_iap_ssh" {
  name        = "allow-iap-ssh"
  network     = google_compute_network.main.name
  description = "Allow SSH via IAP tunnel - SEC-2103"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # IAP's IP range
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["allow-ssh"]
}

# Internal communication - various teams added rules over time
resource "google_compute_firewall" "internal_all" {
  name        = "allow-internal"
  network     = google_compute_network.main.name
  description = "Allow all internal traffic"
  priority    = 1000

  allow {
    protocol = "tcp"
  }

  allow {
    protocol = "udp"
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = ["10.100.0.0/16"]
}

# Legacy rule from datacenter migration - DO NOT DELETE
# Ticket: INFRA-1234
resource "google_compute_firewall" "legacy_datacenter" {
  name        = "allow-legacy-dc"
  network     = google_compute_network.main.name
  description = "Legacy DC connectivity - expires Dec 2024"
  priority    = 900

  allow {
    protocol = "tcp"
    ports    = ["443", "8443", "9090"]
  }

  source_ranges = ["192.168.100.0/24"]  # Old DC range
  target_tags   = ["legacy-dc-access"]
}

# Web tier - public facing
resource "google_compute_firewall" "web_public" {
  name        = "allow-web-public"
  network     = google_compute_network.main.name
  description = "Public web traffic"

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["web-tier"]
}

# Health checks from GCP load balancers
resource "google_compute_firewall" "health_checks" {
  name        = "allow-health-checks"
  network     = google_compute_network.main.name
  description = "Allow GCP health check probes"

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "8080"]
  }

  # GCP health check IP ranges
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["allow-health-check"]
}

# API servers - restricted to internal + VPN
resource "google_compute_firewall" "api_servers" {
  name        = "allow-api-servers"
  network     = google_compute_network.main.name
  description = "API server access - INFRA-5521"

  allow {
    protocol = "tcp"
    ports    = ["8080", "8443", "9443"]
  }

  source_ranges = [
    "10.100.0.0/16",     # Internal
    "10.50.0.0/16",      # Legacy DC
    "172.16.50.0/24",    # VPN users
  ]
  target_tags = ["api-tier"]
}

# Temporary rule for debugging - added by Bob
# TODO: Remove after incident resolved - INC-7821
resource "google_compute_firewall" "temp_debug" {
  name        = "temp-debug-bob-delete-me"
  network     = google_compute_network.main.name
  description = "TEMP: Debugging connectivity issue"
  priority    = 500

  allow {
    protocol = "tcp"
    ports    = ["5000-5100"]
  }

  source_ranges = ["10.100.10.0/24"]
  target_tags   = ["debug"]
}

# Database tier - very restrictive
resource "google_compute_firewall" "db_tier" {
  name        = "allow-db-tier"
  network     = google_compute_network.main.name
  description = "Database access from app tier only"
  priority    = 100

  allow {
    protocol = "tcp"
    ports    = ["3306", "5432", "6379"]  # MySQL, Postgres, Redis
  }

  source_tags = ["api-tier", "worker-tier"]
  target_tags = ["db-tier"]
}

# Deny all other ingress (explicit)
resource "google_compute_firewall" "deny_all_ingress" {
  name        = "deny-all-ingress"
  network     = google_compute_network.main.name
  description = "Default deny all ingress"
  direction   = "INGRESS"
  priority    = 65534

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}
