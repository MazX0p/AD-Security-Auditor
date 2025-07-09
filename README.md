Here's your content formatted neatly in Markdown:  

---

# AD Security Auditor

![Active Directory](https://img.shields.io/badge/Active%20Directory-Security%20Audit-blue)
![Language C#](https://img.shields.io/badge/Language-C%23-green)
![Framework .NET 7.0](https://img.shields.io/badge/Framework-.NET%207.0-purple)
![License MIT](https://img.shields.io/badge/License-MIT-orange)

## Enterprise-Grade Active Directory Security Assessment Platform

The **AD Security Auditor** is a comprehensive security assessment platform designed for enterprise environments to identify vulnerabilities, misconfigurations, and security weaknesses in Active Directory infrastructures. With dual-mode operation for both compliance audits and penetration testing, this solution provides organizations with actionable intelligence to fortify their AD security posture.

```
graph TD
    A[AD Security Auditor] --> B[GRC Mode]
    A --> C[Red Team Mode]
    B --> D[Compliance Checks]
    B --> E[Policy Validation]
    C --> F[Attack Surface Analysis]
    C --> G[Exploit Detection]
    A --> H[Reporting Engine]
    H --> I[HTML Reports]
    H --> J[CSV Exports]
    H --> K[SIEM Integration]
    A --> L[Remediation Tools]
    ```
---

## Key Features

- **Dual Audit Modes:** GRC (Governance, Risk, Compliance) and Red Team (Attack Surface Analysis)
- **Comprehensive Security Checks:** 25+ critical AD security checks across multiple domains
- **Compliance Mapping:** Alignment with NIST, CIS, MITRE ATT&CK frameworks
- **Automated Remediation:** PowerShell scripts for immediate issue resolution
- **Flexible Reporting:** HTML, CSV, and JSON reports
- **SIEM Integration:** Splunk, Elasticsearch, QRadar support
- **Continuous Monitoring:** Scheduled audits with baseline comparisons
- **Credential Security:** Secure authentication handling

---

## Installation

### Prerequisites

- [.NET 7.0 Runtime](https://dotnet.microsoft.com/download/dotnet/7.0)
- Active Directory PowerShell Module
- Read access to Active Directory (minimum: domain user)

---

## Getting Started

### Basic Domain Audit

```bash
ADAuditor --domain=corp.example.com --user=audituser --pass=SecurePass123!
```

### Compliance-Focused Audit (GRC Mode)

```bash
ADAuditor --mode=grc --config=configs/compliance_config.json
```

### Attack Surface Analysis (Red Team Mode)

```bash
ADAuditor --mode=redteam --output=redteam_report.html
```

### Continuous Monitoring

```bash
ADAuditor --continuous --interval=12 --maxruns=48
```

---

## Security Checks

The AD Security Auditor performs comprehensive checks across critical security domains:

| Category            | Checks Included                                               | Compliance Mapping                 |
|---------------------|---------------------------------------------------------------|------------------------------------|
| **Authentication**  | Password policies, Kerberos settings, NTLM                    | NIST 800-53, CIS Benchmark         |
| **Account Security**| Privileged groups, stale accounts, lockout                    | CIS Controls 5, 16                 |
| **Delegation**      | Unconstrained/constrained delegation                          | MITRE ATT&CK T1558                 |
| **Service Security**| Service accounts, LAPS implementation                         | NIST IA-5, CIS 4.1                 |
| **Protocol Security**| LDAP signing, SMBv1, encrypted protocols                     | CIS 1.7, 1.8, 2.3.2                |
| **AD Infrastructure**| AdminSDHolder, Protected Users, Recycle Bin                  | Microsoft Security Baselines       |
| **Red Team Focus**  | ACL backdoors, GPP credentials, DCSync rights                 | MITRE ATT&CK T1003, T1484          |

---

## Sample Report Outputs

- **HTML Executive Summary**  
  
![Screenshot_10](https://github.com/user-attachments/assets/b46714cb-4b1d-4820-9bc9-c4f5ad677c4a)

![Screenshot_9](https://github.com/user-attachments/assets/1d3dc960-5c6b-4aaa-a227-229cc3818dfb)

- **Finding Details**  
  ![Screenshot_11](https://github.com/user-attachments/assets/af9ed37c-42b6-45e7-bd78-9d2aa28a8830)


---

## Configuration

Customize audits using JSON configuration files:

```json
{
  "EnableParallelExecution": true,
  "DisabledChecks": ["PRINT-001", "SHADOW-001"],
  "CustomThresholds": {
    "MinPasswordLength": 14,
    "StaleObjectThreshold": 60,
    "LockoutThreshold": 5
  },
  "PrivilegedGroups": [
    "Domain Admins",
    "Enterprise Admins",
    "Cloud Admins"
  ],
  "OutputDirectory": "C:\\AuditReports",
  "MinReportSeverity": "Medium",
  "EnableSiemIntegration": true,
  "SiemEndpoint": "https://siem.corp.example.com/api/events",
  "SiemToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

## Command Line Reference

| Option       | Description                  | Default Value    |
|--------------|------------------------------|------------------|
| `--mode`     | Audit mode (`grc` / `redteam`) | `grc`           |
| `--domain`   | Target domain FQDN           | Current domain   |
| `--user`     | Authentication username      | Current user     |
| `--pass`     | Authentication password      | N/A              |
| `--config`   | Configuration file path      | N/A              |
| `--continuous`| Enable continuous monitoring| `false`          |
| `--interval` | Hours between scans          | `24`             |
| `--maxruns`  | Maximum monitoring runs (`0`=unlimited)| `0` |
| `--output`   | Custom report output path    | Current directory|
| `--help`     | Show help information        | N/A              |

---

## Security Architecture

**Security Features:**

- Encrypted LDAP communication (LDAPS)
- Secure credential handling
- Least privilege execution
- Signed report outputs
- Audit trail preservation

---

## Compliance Mapping

Full compliance coverage includes:

- NIST 800-53 (IA-5, AC-7)
- CIS Microsoft Windows Benchmarks
- MITRE ATT&CK Framework
- Microsoft Security Compliance Toolkit

---

## Contributing

We welcome contributions from security professionals:

- Report vulnerabilities via responsible disclosure
- Submit pull requests for new security checks
- Improve documentation and translations
- Add support for additional compliance frameworks

Please review our [Contribution Guidelines](CONTRIBUTING.md) before submitting changes.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

---

## Acknowledgments

- Microsoft Active Directory Security Team
- MITRE ATT&CK Framework
- CIS Benchmarks Community
- NIST Cybersecurity Framework

---

**AD Security Auditor – Enterprise Active Directory Protection**  
Copyright © 2023 Mohamed Alzhrani (0xMaz).  
All Rights Reserved.
