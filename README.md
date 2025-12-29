# Atlas CSPM - Cloud Security Posture Management Tool

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.3-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![AWS](https://img.shields.io/badge/AWS-Compatible-yellow.svg)

**A comprehensive open-source Cloud Security Posture Management (CSPM) tool for AWS infrastructure security assessment and compliance auditing.**

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security Checks](#security-checks)
- [Output and Reports](#output-and-reports)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

---

## Overview

**Atlas CSPM** is a command-line security assessment tool designed to audit AWS cloud infrastructure against security best practices and compliance frameworks. It performs automated scanning of AWS services including **S3 buckets**, **EC2 instances**, and **IAM configurations**, identifying misconfigurations and compliance violations against **CIS AWS Foundations Benchmarks**.

### Why Atlas CSPM?

- Comprehensive Coverage: Scans S3, EC2, and IAM services
- CIS Benchmark Compliance: Validates against 40+ CIS AWS Foundations checks
- Real-time Scanning: Interactive CLI with progress tracking
- Detailed Reporting: Multi-format compliance reports with remediation guidance
- Open Source: Free, transparent, and community-driven
- Extensible: Easy to add custom security checks

---

## Features

### Security Scanning

| Service | Checks | Coverage |
|---------|--------|----------|
| **S3** | 20+ checks | Encryption, public access, logging, versioning, lifecycle policies |
| **EC2** | 20+ checks | Security groups, network exposure, AMI encryption, instance metadata |
| **IAM** | 6+ checks | Password policies, MFA, access keys, root account usage |

### Compliance and Reporting

- **CIS Benchmark Mapping**: Aligned with CIS AWS Foundations Benchmarks
- **Severity Classification**: Critical, High, Medium, Low, and Informational findings
- **Compliance Scoring**: Overall compliance vs. non-compliance percentages
- **Detailed Remediation**: Step-by-step fix instructions for each finding

### Core Capabilities

- **Multi-Region Scanning**: Enumerate resources across all AWS regions
- **Resource Discovery**: Automatic AWS resource counting and inventory
- **Interactive Shell**: Ongoing scan and status commands
- **Progress Tracking**: Real-time progress bars during scans
- **Persistent Configuration**: Secure credential storage with MySQL
- **Result Caching**: Query results without re-scanning

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI Interface                          │
│                     (main.py)                               │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ├──> Credential Management (connector.py)
                   │    └──> Database Config (config/dbConfig.py)
                   │
                   ├──> Resource Counter (config/get_resource.py)
                   │
                   ├──> Service Helpers
                   │    ├──> S3 Helper (helper/aws/S3/)
                   │    ├──> EC2 Helper (helper/aws/EC2/)
                   │    └──> IAM Helper (helper/aws/IAM/)
                   │
                   ├──> Data Collectors (collector/*.py)
                   │    └──> AWS API Calls (boto3)
                   │
                   └──> Policy Checkers (plugins/*.py)
                        └──> Security Rule Validation
```

### Data Flow

```
AWS Credentials → Resource Discovery → Service Scanning → Policy Validation → Report Generation
```

Each scan follows a standardized pipeline: **Collection → Analysis → Reporting**

---

## Prerequisites

- **Python**: 3.8 or higher
- **AWS Account**: With programmatic access credentials
- **MySQL**: Database for credential persistence
- **Network Access**: Outbound HTTPS to AWS APIs

### Required AWS IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeImages",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "iam:GetAccountPasswordPolicy",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccountSummary",
        "iam:GenerateCredentialReport",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/AbishekPonmudi/Atlas-CSMP.git
cd Atlas-CSMP
```

### 2. Install Dependencies

```bash
pip install -r requirement.txt
```

### Required Python Packages

- `boto3` - AWS SDK for Python
- `tabulate` - Pretty table formatting
- `mysql-connector-python` - MySQL database connectivity
- `argparse` - Command-line argument parsing

### 3. Configure MySQL Database

Create a database and configure connection details in `config/dbConfig.py`:

```python
DB_CONFIG = {
    'host': 'localhost',
    'user': 'your_username',
    'password': 'your_password',
    'database': 'Atlas_cspm'
}
```

Create required tables:

```sql
CREATE TABLE aws_credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    access_key VARCHAR(128) NOT NULL,
    secret_key VARCHAR(128) NOT NULL,
    region VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## Configuration

### First-Time Setup

On first run, the tool will prompt for AWS credentials:

```bash
python main.py
```

You'll be asked to provide:

1. **AWS Access Key ID** (16-128 alphanumeric characters)
2. **AWS Secret Access Key** (16-128 characters)
3. **Default AWS Region** (e.g., `us-east-1`)

Credentials are validated and securely stored in MySQL for future use.

### Credential Validation Rules

- **Access Key**: Non-empty, 16-128 characters, alphanumeric
- **Secret Key**: Non-empty, 16-128 characters
- **Region**: Valid AWS region identifier

---

## Usage

### Basic Scan

Run a complete infrastructure scan:

```bash
python main.py
```

### Interactive Shell Commands

Once the initial scan completes, you enter an interactive shell:

```
Atlas@shell> cloud scan          # Run a new scan
Atlas@shell> cloud status        # Display cached results
Atlas@shell> exit          # Exit the tool
```

### Command Reference

| Command | Description |
|---------|-------------|
| `cloud scan` | Execute a new security scan across all services |
| `cloud status` | Display results from the last scan (cached) |
| `cloud exit` | Exit the interactive shell |

---

## Security Checks

### S3 Security Checks (CIS 2.1.x)

- Bucket encryption at rest
- Server access logging enabled
- Versioning enabled
- Public access block configuration
- Bucket policy security
- MFA Delete enabled
- Lifecycle policies configured
- Object lock enabled
- Replication configuration
- Default encryption settings

### EC2 Security Checks

- Security group ingress rules (0.0.0.0/0 exposure)
- Security group egress rules
- IMDSv2 enforcement (metadata service)
- EBS volume encryption
- AMI encryption
- Public IP assignment
- Instance profile attachment
- Detailed monitoring enabled
- Termination protection
- User data scripts security

### IAM Security Checks

- Password policy compliance
- MFA enabled for users
- Root account usage
- Access key rotation
- Unused credentials
- Privilege escalation paths

---

## Output and Reports

### Report Formats

The tool generates three comprehensive tables:

#### 1. Scan Overview by Service

```
╒═══════════╤════════════╤═════════╤═════════╤═════════╤═══════╕
│ Service   │   Critical │    High │  Passed │     Low │ Muted │
╞═══════════╪════════════╪═════════╪═════════╪═════════╪═══════╡
│ S3        │          5 │      12 │       3 │       0 │     0 │
├───────────┼────────────┼─────────┼─────────┼─────────┼───────┤
│ EC2       │          2 │       8 │      10 │       0 │     0 │
├───────────┼────────────┼─────────┼─────────┼─────────┼───────┤
│ IAM       │          1 │       3 │       2 │       0 │     0 │
╘═══════════╧════════════╧═════════╧═════════╧═════════╧═══════╛
```

#### 2. Detailed Scan Summary

Shows percentage distributions across:
- Status categories (Pass, Fail, Warning, Error)
- Severity levels (Critical, High, Medium, Low)

#### 3. CIS Benchmark Compliance Status

```
Overall Compliance: 45.2%
Non-Compliance: 54.8%
Total Resources Scanned: 127
```

### Finding Data Structure

Each security finding includes:

- **Category**: AWS service (S3, EC2, IAM)
- **Check**: Specific check identifier (e.g., CIS 2.1.1)
- **Description**: Human-readable issue description
- **Resource**: ARN or identifier of affected resource
- **Status**: PASS, FAIL, WARN, ERROR
- **Remediation**: Step-by-step fix instructions
- **Severity**: Critical, High, Medium, Low

### Color-Coded Output

- **Red**: Critical/Failed checks
- **Yellow**: Warnings
- **Green**: Passed checks
- **White**: Informational/Error

---

## Development

### Project Structure

```
infrastructure_scanner_for_cloud/
├── main.py                 # Application entry point & CLI
├── connector.py            # AWS credential management
├── requirement.txt         # Python dependencies
├── config/
│   ├── dbConfig.py        # Database configuration
│   └── get_resource.py    # Resource enumeration
├── collector/             # AWS API data collection
│   ├── s3_collector.py
│   ├── ec2_collector.py
│   └── iam_collector.py
├── plugins/               # Security policy checkers
│   ├── s3_checks.py
│   ├── ec2_checks.py
│   └── iam_checks.py
├── helper/
│   └── aws/              # Service-specific helpers
│       ├── S3/
│       ├── EC2/
│       └── IAM/
└── test-live/            # Test scripts
```

### Adding New Security Checks

1. **Create Collector Function** (`collector/`)

```python
def collect_new_resource_data(session, region):
    """Collect data for new resource type"""
    client = session.client('service', region_name=region)
    # AWS API calls
    return resource_data
```

2. **Create Policy Checker** (`plugins/`)

```python
def check_new_security_policy(resource_data):
    """Validate against security policy"""
    findings = []
    for resource in resource_data:
        if not meets_policy(resource):
            findings.append({
                'Category': 'SERVICE',
                'Check': 'CIS X.X.X',
                'Description': 'Issue description',
                'Resource': resource['arn'],
                'Status': 'FAIL',
                'Remediation': 'Fix steps',
                'Critical': 1
            })
    return findings
```

3. **Integrate into Pipeline** (`helper/`)

```python
def collect_and_check_new_service(session, regions, callback):
    """Orchestrate collection and checking"""
    data = collect_new_resource_data(session, regions)
    findings = check_new_security_policy(data)
    callback(findings)
```

### Testing

```bash
# Run test suite
python test.py

# Test individual service
python -m unittest test_live/test_s3.py
```

---

## Contributing

We welcome contributions! Please follow these guidelines:

### How to Contribute

1. **Fork the Repository**
   ```bash
   git fork https://github.com/AbishekPonmudi/Atlas-CSMP.git
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/new-security-check
   ```

3. **Make Your Changes**
   - Follow existing code style
   - Add tests for new functionality
   - Update documentation

4. **Commit Changes**
   ```bash
   git commit -m "feat: Add S3 bucket tagging check"
   ```

5. **Push to Your Fork**
   ```bash
   git push origin feature/new-security-check
   ```

6. **Submit a Pull Request**
   - Describe your changes
   - Reference any related issues
   - Ensure CI checks pass

### Contribution Areas

- New security checks and policies
- Additional AWS service support (RDS, Lambda, CloudTrail, etc.)
- Enhanced reporting formats (JSON, CSV, HTML)
- Bug fixes and performance improvements
- Documentation improvements
- Test coverage expansion

### Code Style

- Follow PEP 8 guidelines
- Use meaningful variable names
- Add docstrings to functions
- Keep functions focused and modular

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Abishek Ponmudi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## Documentation

For comprehensive documentation, visit:

**[DeepWiki Documentation](https://deepwiki.com/AbishekPonmudi/infrastructure_scanner_for_cloud)**

### Documentation Sections

- **[Overview](https://deepwiki.com/AbishekPonmudi/infrastructure_scanner_for_cloud/1-overview)** - System architecture and design
- **[Getting Started](https://deepwiki.com/AbishekPonmudi/infrastructure_scanner_for_cloud/2-getting-started)** - Quick start guide
- **[Installation](https://deepwiki.com/AbishekPonmudi/infrastructure_scanner_for_cloud/2.1-installation-and-setup)** - Detailed setup instructions
- **[Configuration](https://deepwiki.com/AbishekPonmudi/infrastructure_scanner_for_cloud/2.2-configuring-aws-credentials)** - AWS credential setup
- **[Architecture](https://deepwiki.com/AbishekPonmudi/infrastructure_scanner_for_cloud/3-architecture)** - Technical architecture deep-dive
- **[Security Checks Catalog](https://deepwiki.com/AbishekPonmudi/infrastructure_scanner_for_cloud/8-security-checks-catalog)** - Complete list of checks
- **[Development Guide](https://deepwiki.com/AbishekPonmudi/infrastructure_scanner_for_cloud/9-development-guide)** - Extending the tool
- **[Troubleshooting](https://deepwiki.com/AbishekPonmudi/infrastructure_scanner_for_cloud/10-troubleshooting)** - Common issues and solutions

---

## Support

### Getting Help

- **Documentation**: Check the [DeepWiki](https://deepwiki.com/AbishekPonmudi/infrastructure_scanner_for_cloud)
- **Bug Reports**: Open an [issue](https://github.com/AbishekPonmudi/infrastructure_scanner_for_cloud/issues)
- **Feature Requests**: Submit an [issue](https://github.com/AbishekPonmudi/infrastructure_scanner_for_cloud/issues) with the `enhancement` label
- **Discussions**: Join the [GitHub Discussions](https://github.com/AbishekPonmudi/infrastructure_scanner_for_cloud/discussions)

### Reporting Issues

When reporting bugs, please include:

1. Python version (`python --version`)
2. Operating system
3. Complete error message
4. Steps to reproduce
5. Expected vs. actual behavior

---

## Acknowledgments

- **CIS Benchmarks**: Security checks aligned with [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- **AWS SDK**: Built with [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- **Community**: Thanks to all contributors and users

---

## Roadmap

### Upcoming Features

- Multi-cloud support (Azure, GCP)
- Additional AWS services (RDS, Lambda, CloudTrail, VPC)
- Web-based dashboard UI
- Scheduled scanning with notifications
- Export to SIEM integrations
- Custom policy engine
- Compliance frameworks (PCI-DSS, HIPAA, SOC 2)
- Automated remediation scripts
- Docker containerization
- CI/CD integration examples

---

## Project Stats

![GitHub stars](https://img.shields.io/github/stars/AbishekPonmudi/infrastructure_scanner_for_cloud?style=social)
![GitHub forks](https://img.shields.io/github/forks/AbishekPonmudi/infrastructure_scanner_for_cloud?style=social)
![GitHub issues](https://img.shields.io/github/issues/AbishekPonmudi/infrastructure_scanner_for_cloud)
![GitHub pull requests](https://img.shields.io/github/issues-pr/AbishekPonmudi/infrastructure_scanner_for_cloud)

---

<div align="center">

**Built by [Abishek Ponmudi](https://github.com/AbishekPonmudi)**

If you find this project helpful, please consider giving it a star.

[Report Bug](https://github.com/AbishekPonmudi/infrastructure_scanner_for_cloud/issues) · [Request Feature](https://github.com/AbishekPonmudi/infrastructure_scanner_for_cloud/issues) · [Documentation](https://deepwiki.com/AbishekPonmudi/infrastructure_scanner_for_cloud)

</div>
