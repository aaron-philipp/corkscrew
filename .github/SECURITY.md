# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in CorkScrew, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email the maintainer directly (see profile for contact)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes

You can expect:
- Acknowledgment within 48 hours
- Status update within 7 days
- Credit in the fix announcement (unless you prefer anonymity)

## Scope

CorkScrew is a static analysis tool that reads Terraform files. Security concerns include:

- Path traversal when reading files
- Denial of service via malformed input
- Code injection (the tool does not execute Terraform)

## Out of Scope

- Issues in dependencies (report to those projects)
- Social engineering
- Physical security
