# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < latest | :x:               |

Only the latest release is supported with security updates. We recommend always using the most recent version.

## Reporting a Vulnerability

If you discover a security vulnerability in Plumber, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use one of the following methods:

1. **GitHub Security Advisories** (preferred): Use [GitHub's private vulnerability reporting](https://github.com/getplumber/plumber/security/advisories/new) to submit a report directly.
2. **Email**: Send details to the maintainers via the contact information in the repository.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity, but we aim for:
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: Next release

### Disclosure policy

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). We will work with you to understand and address the issue before any public disclosure.

## Security Best Practices for CI/CD

Plumber itself is a CI/CD compliance scanner. We practice what we preach:

- All GitHub Actions are pinned by SHA commit hash
- Workflow permissions follow the principle of least privilege
- Release artifacts include SLSA Level 3 provenance attestations
- Dependencies are monitored with Dependabot
- Code is analyzed with CodeQL (SAST)
- Container images are scanned with Grype
