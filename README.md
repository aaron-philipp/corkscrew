# CorkScrew

**AWS Terraform Synthetic Network Detector**

CorkScrew analyzes Terraform configurations to detect whether AWS infrastructure is synthetically generated (honeypots, deception environments, lab setups) versus organically grown production systems.

## Why CorkScrew?

Real production infrastructure accumulates artifacts over time - legacy naming, configuration drift, troubleshooting remnants, and operational cruft. Synthetic infrastructure, whether honeypots or freshly generated lab environments, tends to be suspiciously "clean" and uniform.

CorkScrew identifies these telltale signs to help security researchers, red teams, and infrastructure auditors distinguish real targets from decoys.

## Installation

```bash
pip install corkscrew
```

Or install from source:

```bash
git clone https://github.com/aaron-philipp/corkscrew.git
cd corkscrew
pip install -e .
```

## Quick Start

```bash
# Analyze a directory of Terraform files
corkscrew /path/to/terraform/

# Analyze a single file
corkscrew main.tf

# Verbose output with detailed flags
corkscrew /path/to/terraform/ -v

# JSON output for automation
corkscrew /path/to/terraform/ --json

# Just the score (for scripting)
corkscrew /path/to/terraform/ -q
```

## Score Interpretation

| Score | Verdict | Meaning |
|-------|---------|---------|
| 75-100 | Highly Likely Synthetic | Strong indicators of honeypot/generated infrastructure |
| 50-74 | Probable Synthetic | Significant synthetic characteristics |
| 30-49 | Suspicious | Mixed signals - warrants investigation |
| 0-29 | Likely Organic | Appears to be real, production infrastructure |

## Detection Heuristics

CorkScrew analyzes seven categories of indicators:

### 1. Naming Pattern Analysis
- Sequential/formulaic naming (`web-server-01`, `web-server-02`)
- Too-perfect naming conventions
- Missing legacy artifacts (`old-server`, `test-dont-delete`, `bobs-thing`)
- No typos or inconsistencies

### 2. Resource Symmetry
- Identical subnet configurations across AZs
- Security groups that are too balanced/mirrored
- Perfect CIDR block allocation (no gaps, no mixed sizes)
- Uniform instance types across all resources
- Perfect AZ distribution

### 3. Temporal Indicators
- Identical timestamps suggesting batch creation
- No version indicators (`-v1`, `-v2`, `-rev1`)
- Missing lifecycle cruft (no deprecated/backup resources)
- No resource migration artifacts (`moved`, `import` blocks)
- No creation timestamp tags

### 4. Structural Realism
- Missing operational resources (bastion hosts, NAT gateways, VPC endpoints)
- No logging/monitoring infrastructure (CloudWatch, flow logs)
- Too-clean security groups (no accumulated exceptions)
- No cross-account references or VPC peering
- Missing IAM configuration

### 5. Configuration Entropy
- Instance types too uniform
- Single region deployment
- Missing or too-perfect tagging
- No hardcoded IPs or legacy workarounds
- Single AMI across all instances

### 6. Organic Signals
- No commented-out code
- No TODOs or FIXMEs
- No ticket references (JIRA-1234, etc.)
- No debug/troubleshooting configurations
- No environment-specific overrides

### 7. Code Artifacts
- No lifecycle blocks
- Simple count-based iteration
- No explicit dependencies
- No data sources referencing existing resources
- No module usage
- Simple provider configuration

## Example Output

```
╔═══════════════════════════ CorkScrew Analysis ═══════════════════════════╗
║ Synthetic Score: 67.7/100                                                ║
║                                                                          ║
║ PROBABLE SYNTHETIC                                                       ║
║                                                                          ║
║ Confidence: HIGH                                                         ║
╚═════════════════ AWS Terraform Synthetic Network Detector ═══════════════╝

                          Category Breakdown
┌───────────────────────┬───────┬───────┬─────────────────────────────┐
│ Category              │ Score │ Flags │ Top Concern                 │
├───────────────────────┼───────┼───────┼─────────────────────────────┤
│ Resource Symmetry     │ 100%  │   5   │ Uniform Subnet Sizing       │
│ Structural Realism    │ 100%  │   7   │ No Bastion/Jump Host        │
│ Naming Patterns       │  58%  │   3   │ Sequential/Formulaic Naming │
│ Temporal Indicators   │  55%  │   3   │ No Version Indicators       │
│ Organic Signals       │  55%  │   3   │ No Ticket References        │
│ Configuration Entropy │  50%  │   3   │ Uniform Tag Keys            │
│ Code Artifacts        │  30%  │   2   │ No Data Sources             │
└───────────────────────┴───────┴───────┴─────────────────────────────┘

┌────────────────────────────────── Summary ──────────────────────────────────┐
│                                                                             │
│  This infrastructure has significant synthetic characteristics but some     │
│  organic elements. Primary concerns: Resource Symmetry, Structural          │
│  Realism, Naming Patterns. Analysis based on 26 triggered flags with high   │
│  confidence.                                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## JSON Output Schema

```json
{
  "synthetic_score": 67.7,
  "confidence": "high",
  "verdict": "PROBABLE SYNTHETIC",
  "categories": [
    {
      "name": "Naming Patterns",
      "score": 57.6,
      "flags": [
        {
          "name": "Sequential/Formulaic Naming",
          "severity": 0.42,
          "description": "Resources follow predictable sequential naming patterns",
          "evidence": ["web-server-01", "web-server-02", "web-server-03"]
        }
      ]
    }
  ],
  "summary": "This infrastructure has significant synthetic characteristics..."
}
```

## Use Cases

- **Red Team Operations**: Identify honeypots and deception infrastructure before engaging
- **Security Research**: Analyze suspicious infrastructure in threat intelligence
- **Infrastructure Auditing**: Detect freshly provisioned or lab environments
- **Deception Validation**: Test your own honeypots to ensure they appear organic
- **CTF Challenges**: Distinguish real targets from decoys

## Requirements

- Python 3.9+
- Dependencies: `click`, `rich`, `python-hcl2`

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas of interest:
- Additional detection heuristics
- Support for other cloud providers (Azure, GCP)
- Support for other IaC tools (CloudFormation, Pulumi)
- Machine learning-based detection

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for authorized security testing, research, and educational purposes only. Always ensure you have proper authorization before analyzing infrastructure you do not own.

## Author

Created by [aaron-philipp](https://github.com/aaron-philipp)
