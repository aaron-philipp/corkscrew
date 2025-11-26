# Changelog

All notable changes to CorkScrew will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-11-26

### Added

- Initial release of CorkScrew
- Core analysis engine for detecting synthetic Terraform configurations
- Seven detection categories:
  - **Naming Patterns**: Sequential naming, missing legacy artifacts, perfect consistency
  - **Resource Symmetry**: Uniform subnets, balanced security groups, perfect CIDR allocation
  - **Temporal Indicators**: Identical timestamps, missing version indicators, no lifecycle cruft
  - **Structural Realism**: Missing operational resources, no monitoring, no cross-account references
  - **Configuration Entropy**: Uniform instance types, single region, perfect tagging
  - **Organic Signals**: No comments, TODOs, ticket references, or debug configs
  - **Code Artifacts**: No lifecycle blocks, data sources, or modules
- CLI interface with multiple output formats:
  - Pretty terminal output with Rich formatting
  - JSON output for automation
  - Quiet mode for scripting
  - Verbose mode for detailed flag information
- Sample Terraform configurations for testing (synthetic and organic)
- Windows console encoding fix for proper Unicode display

### Detection Heuristics

Initial set of 26+ detection flags across all categories, including:

- Sequential/formulaic naming detection
- Legacy naming artifact detection
- Subnet sizing uniformity
- CIDR block sequencing
- Security group structure analysis
- Instance type distribution
- AZ balance checking
- Timestamp analysis
- Version indicator detection
- Lifecycle cruft detection
- Bastion/jump host detection
- NAT gateway detection
- VPC flow log detection
- CloudWatch monitoring detection
- VPC endpoint detection
- IAM configuration detection
- Cross-account/peering detection
- Security group cleanliness analysis
- Tag consistency analysis
- Hardcoded IP detection
- AMI uniformity detection
- Region diversity checking
- Ticket reference detection
- TODO/FIXME detection
- Commented code detection
- Debug configuration detection
- Lifecycle block detection
- Data source detection
- Module usage detection
- Provider configuration analysis
