"""Tests for the CorkScrew analyzer."""
from pathlib import Path

import pytest

from corkscrew.analyzer import AnalysisResult, TerraformAnalyzer


@pytest.fixture
def analyzer():
    """Create a fresh analyzer instance."""
    return TerraformAnalyzer()


@pytest.fixture
def samples_dir():
    """Get the samples directory path."""
    return Path(__file__).parent.parent / "samples"


class TestSyntheticDetection:
    """Test detection of synthetic infrastructure."""

    def test_synthetic_sample_scores_high(self, analyzer, samples_dir):
        """Synthetic sample should score above 50."""
        analyzer.parse_directory(samples_dir / "synthetic")
        result = analyzer.analyze()

        assert result.synthetic_score >= 50
        assert result.confidence in ["medium", "high"]
        assert result.provider == "aws"

    def test_organic_sample_scores_low(self, analyzer, samples_dir):
        """Organic sample should score below 30."""
        analyzer.parse_directory(samples_dir / "organic")
        result = analyzer.analyze()

        assert result.synthetic_score < 30
        assert result.confidence in ["medium", "high"]
        assert result.provider == "aws"


class TestGCPDetection:
    """Test GCP infrastructure detection."""

    def test_gcp_synthetic_sample_scores_high(self, analyzer, samples_dir):
        """GCP synthetic sample should score above 50."""
        gcp_synthetic = samples_dir / "gcp" / "synthetic"
        if gcp_synthetic.exists():
            analyzer.parse_directory(gcp_synthetic)
            result = analyzer.analyze()

            assert result.synthetic_score >= 50
            assert result.provider == "gcp"

    def test_gcp_organic_sample_scores_low(self, analyzer, samples_dir):
        """GCP organic sample should score below 30."""
        gcp_organic = samples_dir / "gcp" / "organic"
        if gcp_organic.exists():
            analyzer.parse_directory(gcp_organic)
            result = analyzer.analyze()

            assert result.synthetic_score < 30
            assert result.provider == "gcp"

    def test_gcp_provider_detected(self, analyzer, tmp_path):
        """GCP resources should be detected as GCP provider."""
        tf_content = '''
resource "google_compute_network" "main" {
  name = "my-vpc"
}

resource "google_compute_subnetwork" "subnet" {
  name          = "my-subnet"
  ip_cidr_range = "10.0.0.0/24"
  network       = google_compute_network.main.id
}
'''
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(tf_content)

        analyzer.parse_file(tf_file)
        result = analyzer.analyze()

        assert result.provider == "gcp"

    def test_gcp_sequential_naming_detected(self, analyzer, tmp_path):
        """Sequential naming should be detected in GCP resources."""
        tf_content = '''
resource "google_compute_instance" "web-server-01" {
  name         = "web-server-01"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
}

resource "google_compute_instance" "web-server-02" {
  name         = "web-server-02"
  machine_type = "e2-medium"
  zone         = "us-central1-b"
}

resource "google_compute_instance" "web-server-03" {
  name         = "web-server-03"
  machine_type = "e2-medium"
  zone         = "us-central1-c"
}
'''
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(tf_content)

        analyzer.parse_file(tf_file)
        result = analyzer.analyze()

        assert result.provider == "gcp"
        naming_cat = next(c for c in result.categories if c.name == "Naming Patterns")
        flag_names = [f.name for f in naming_cat.flags]
        assert "Sequential/Formulaic Naming" in flag_names

    def test_gcp_uniform_subnet_sizing(self, analyzer, tmp_path):
        """Uniform GCP subnet sizes should be flagged."""
        tf_content = '''
resource "google_compute_subnetwork" "a" {
  name          = "subnet-a"
  ip_cidr_range = "10.0.1.0/24"
  region        = "us-central1"
  network       = "my-vpc"
}

resource "google_compute_subnetwork" "b" {
  name          = "subnet-b"
  ip_cidr_range = "10.0.2.0/24"
  region        = "us-central1"
  network       = "my-vpc"
}

resource "google_compute_subnetwork" "c" {
  name          = "subnet-c"
  ip_cidr_range = "10.0.3.0/24"
  region        = "us-central1"
  network       = "my-vpc"
}
'''
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(tf_content)

        analyzer.parse_file(tf_file)
        result = analyzer.analyze()

        assert result.provider == "gcp"
        symmetry_cat = next(c for c in result.categories if c.name == "Resource Symmetry")
        flag_names = [f.name for f in symmetry_cat.flags]
        assert "Uniform Subnet Sizing" in flag_names


class TestNamingPatterns:
    """Test naming pattern detection."""

    def test_sequential_naming_detected(self, analyzer, tmp_path):
        """Sequential naming should be flagged."""
        tf_content = '''
resource "aws_instance" "web-server-01" {
  ami           = "ami-12345"
  instance_type = "t3.medium"
}

resource "aws_instance" "web-server-02" {
  ami           = "ami-12345"
  instance_type = "t3.medium"
}

resource "aws_instance" "web-server-03" {
  ami           = "ami-12345"
  instance_type = "t3.medium"
}
'''
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(tf_content)

        analyzer.parse_file(tf_file)
        result = analyzer.analyze()

        # Check that naming patterns category has flags
        naming_cat = next(c for c in result.categories if c.name == "Naming Patterns")
        flag_names = [f.name for f in naming_cat.flags]

        assert "Sequential/Formulaic Naming" in flag_names


class TestResourceSymmetry:
    """Test resource symmetry detection."""

    def test_uniform_subnet_sizing(self, analyzer, tmp_path):
        """Uniform subnet sizes should be flagged."""
        tf_content = '''
resource "aws_subnet" "a" {
  cidr_block = "10.0.1.0/24"
}

resource "aws_subnet" "b" {
  cidr_block = "10.0.2.0/24"
}

resource "aws_subnet" "c" {
  cidr_block = "10.0.3.0/24"
}
'''
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(tf_content)

        analyzer.parse_file(tf_file)
        result = analyzer.analyze()

        symmetry_cat = next(c for c in result.categories if c.name == "Resource Symmetry")
        flag_names = [f.name for f in symmetry_cat.flags]

        assert "Uniform Subnet Sizing" in flag_names
        assert "Sequential CIDR Allocation" in flag_names


class TestResultFormat:
    """Test result formatting."""

    def test_to_dict_format(self, analyzer, samples_dir):
        """Result should serialize to expected dict format."""
        analyzer.parse_directory(samples_dir / "synthetic")
        result = analyzer.analyze()

        d = result.to_dict()

        assert "synthetic_score" in d
        assert "confidence" in d
        assert "verdict" in d
        assert "categories" in d
        assert "summary" in d
        assert "provider" in d

        assert isinstance(d["synthetic_score"], float)
        assert d["confidence"] in ["low", "medium", "high"]
        assert d["provider"] in ["aws", "gcp", "multi", "unknown"]

    def test_verdict_thresholds(self, analyzer):
        """Test verdict based on score thresholds."""
        result = AnalysisResult(synthetic_score=80, confidence="high", provider="aws")
        assert "HIGHLY LIKELY SYNTHETIC" in result.to_dict()["verdict"]

        result = AnalysisResult(synthetic_score=60, confidence="high", provider="aws")
        assert "PROBABLE SYNTHETIC" in result.to_dict()["verdict"]

        result = AnalysisResult(synthetic_score=40, confidence="high", provider="aws")
        assert "SUSPICIOUS" in result.to_dict()["verdict"]

        result = AnalysisResult(synthetic_score=20, confidence="high", provider="aws")
        assert "LIKELY ORGANIC" in result.to_dict()["verdict"]


class TestMultiCloudDetection:
    """Test multi-cloud provider detection."""

    def test_multi_cloud_detected(self, analyzer, tmp_path):
        """Mixed AWS and GCP resources should detect as multi-cloud."""
        tf_content = '''
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "google_compute_network" "main" {
  name = "my-vpc"
}
'''
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(tf_content)

        analyzer.parse_file(tf_file)
        result = analyzer.analyze()

        assert result.provider == "multi"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_directory_raises(self, analyzer, tmp_path):
        """Empty directory should raise ValueError."""
        with pytest.raises(ValueError, match="No .tf files found"):
            analyzer.parse_directory(tmp_path)

    def test_minimal_config(self, analyzer, tmp_path):
        """Minimal config should analyze without error."""
        tf_content = '''
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
'''
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(tf_content)

        analyzer.parse_file(tf_file)
        result = analyzer.analyze()

        assert result.synthetic_score >= 0
        assert result.synthetic_score <= 100
        assert result.provider == "aws"

    def test_unknown_provider(self, analyzer, tmp_path):
        """Unknown resource types should result in unknown provider."""
        tf_content = '''
resource "some_unknown_resource" "main" {
  name = "test"
}
'''
        tf_file = tmp_path / "main.tf"
        tf_file.write_text(tf_content)

        analyzer.parse_file(tf_file)
        result = analyzer.analyze()

        assert result.provider == "unknown"
