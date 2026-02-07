# Domain Security Scanner - Python Version

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Batch check domain mail security configuration including MX, SPF, DKIM, DMARC records with risk assessment and remediation recommendations.

## Features

- ✅ **Batch Scanning**: Check dozens to hundreds of domains at once
- 🔍 **Complete Check**: Covers MX, SPF, DKIM, DMARC, and A records
- 📊 **Security Scoring**: Automatic 0-100 security score calculation
- 🎯 **Risk Classification**: Auto-categorize as Full/Good/Basic Protection or High Risk
- 📝 **Detailed Reports**: Generate comprehensive CSV format reports
- 💡 **Fix Recommendations**: Provide specific DNS record configuration examples
- 🌐 **Multi-language**: Full English interface and reports
- ⚡ **Cross-platform**: Supports Windows, Linux, macOS
- 🚀 **Parallel Scanning**: Multi-threaded acceleration support (optional)

## System Requirements

- Python 3.7 or higher
- Internet connection (for DNS queries)

Check Python version:
```bash
python --version
# or
python3 --version
```

## Installation

### 1. Clone the Project
```bash
git clone https://github.com/yourusername/domain-security-scanner.git
cd domain-security-scanner
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install dnspython colorama
```

### 3. Verify Installation
```bash
python domain_security_scanner.py --help
```

## Usage

### Basic Usage

**Read domains from file:**
```bash
python domain_security_scanner.py -f domains.txt
```

`domains.txt` format (one domain per line):
```
example.com
test.org
mycompany.com
```

**Specify domains directly:**
```bash
python domain_security_scanner.py -d example.com test.org mycompany.com
```

### Advanced Usage

**Custom output directory:**
```bash
python domain_security_scanner.py -f domains.txt -o ./reports
```

**Adjust retry count and delay:**
```bash
python domain_security_scanner.py -f domains.txt --max-retries 3 --retry-delay 1.0
```

**Custom DKIM selectors:**
```bash
python domain_security_scanner.py -f domains.txt --dkim-selectors default,google,amazonses,mailgun
```

**Enable parallel scanning (faster):**
```bash
python domain_security_scanner.py -f domains.txt --parallel 5
```

### Parameter Reference

| Parameter | Short | Description | Default |
|-----------|-------|-------------|---------|
| `--file` | `-f` | Domain list file path | - |
| `--domains` | `-d` | Specify domains directly (space-separated) | - |
| `--output` | `-o` | Report output directory | `.` (current) |
| `--max-retries` | - | DNS query retry count on failure | `2` |
| `--retry-delay` | - | Retry delay (seconds) | `0.5` |
| `--query-delay` | - | Delay between domain queries (seconds) | `0.3` |
| `--dkim-selectors` | - | DKIM selectors (comma-separated) | `default,google,selector1...` |
| `--parallel` | - | Number of parallel scan threads | `1` (sequential) |

## Output Reports

The script generates three files:

### 1. Detailed Scan Report (CSV)
`domain_security_report_YYYYMMDD_HHMMSS.csv`

Contains complete check results for each domain, can be opened in Excel or Google Sheets.

### 2. High Risk Domain List (TXT)
`high_risk_domains_YYYYMMDD_HHMMSS.txt`

Lists all high-risk domains requiring immediate attention.

### 3. Recommendations Report (TXT)
`recommendations_YYYYMMDD_HHMMSS.txt`

Includes:
- Priority action items
- Specific DNS record configuration examples
- Categorized domain lists

## Security Score Calculation

| Item | Score |
|------|-------|
| Has MX record | +20 points |
| Has SPF record | +30 points |
| Has DKIM record | +25 points |
| Has DMARC record | +25 points |
| DMARC policy `reject` | Extra +10 points |
| DMARC policy `quarantine` | Extra +5 points |

**Score Grades:**
- 90-100: Excellent (Full Protection)
- 70-89: Good
- 50-69: Fair
- 30-49: Needs Improvement
- 0-29: Critical

## Configuration Status Explained

| Status | Description |
|--------|-------------|
| **Full Protection (Best Practice)** | Has MX, SPF, DKIM, DMARC with `reject` policy |
| **Full Protection** | Has MX, SPF, DKIM, DMARC |
| **Good Protection (Missing DKIM)** | Has MX, SPF, DMARC |
| **Basic Protection** | Has MX, SPF |
| **High Risk (Missing SPF)** | Has MX but no SPF, vulnerable to email spoofing |
| **Abnormal Configuration** | SPF only without MX |
| **No Mail Configuration** | No mail-related records configured |

## Usage Examples

### Example 1: Quick Scan Few Domains
```bash
python domain_security_scanner.py -d google.com microsoft.com apple.com
```

### Example 2: Scan from File with Output Path
```bash
python domain_security_scanner.py -f my_domains.txt -o /home/user/reports
```

### Example 3: Parallel Scan Large List (Faster)
```bash
python domain_security_scanner.py -f large_list.txt --parallel 5 --query-delay 0.5
```

### Example 4: Check Specific Email Provider DKIM
```bash
# Only check Google Workspace and Microsoft 365 DKIM
python domain_security_scanner.py -f domains.txt --dkim-selectors google,selector1,selector2
```

## Performance Notes

### Scan Speed
- **Sequential scan** (default): ~1-3 seconds per domain, 100 domains in 3-5 minutes
- **Parallel scan** (`--parallel 5`): 3-4x faster, 100 domains in 1-2 minutes

### Recommended Settings
- Less than 50 domains: Use default sequential scan
- 50-200 domains: `--parallel 3`
- 200+ domains: `--parallel 5` (avoid triggering DNS rate limits)

## Remediation Guide

### SPF Record Examples

**Basic setup (allow MX servers to send):**
```
v=spf1 mx ~all
```

**Google Workspace:**
```
v=spf1 include:_spf.google.com ~all
```

**Microsoft 365:**
```
v=spf1 include:spf.protection.outlook.com ~all
```

**Multiple sources:**
```
v=spf1 mx include:_spf.google.com include:servers.mcsv.net ~all
```

### DMARC Record Examples

**Monitoring mode (beginner recommended):**
```
v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com
```

**Quarantine mode:**
```
v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@yourdomain.com
```

**Reject mode (strictest):**
```
v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@yourdomain.com
```

### DKIM Setup

DKIM must be configured through your email service provider:

- **Google Workspace**: Admin Console > Apps > Google Workspace > Gmail > Authenticate Email
- **Microsoft 365**: Exchange Admin Center > Protection > DKIM
- **AWS SES**: SES Console > Verified Identities > DKIM


## Use Cases

- 🏢 Enterprise IT administrators checking multiple domain mail security
- 🔒 Security auditors performing email security assessments
- 🌐 MSPs (Managed Service Providers) managing client domains
- 📊 Regular checks for domain configuration best practices
- 🚀 Configuration verification before/after domain migration
- 🐧 Automated scanning in Linux/macOS environments

## License

MIT License - See [LICENSE](LICENSE) file for details

## Contributing

Issues and Pull Requests are welcome!

### Development Guidelines
- Follow PEP 8 coding style
- Add docstrings for function descriptions
- Test various domain configuration scenarios
- Update CHANGELOG

## Changelog

### v2.0 (2026-02-04)
- ✨ Python version initial release
- ✨ Added DKIM record checking
- ✨ Added security score calculation (0-100)
- ✨ Command-line argument support
- ✨ Parallel scanning support (multi-threaded)
- ✨ Cross-platform support (Windows/Linux/macOS)
- 📝 Complete parameter documentation

## Related Resources

- [RFC 7208 - SPF](https://tools.ietf.org/html/rfc7208)
- [RFC 6376 - DKIM](https://tools.ietf.org/html/rfc6376)
- [RFC 7489 - DMARC](https://tools.ietf.org/html/rfc7489)
- [MXToolbox](https://mxtoolbox.com/) - Online DNS checking tool
- [dnspython Documentation](https://dnspython.readthedocs.io/)

## Author

This is a demonstration version. Please remember to update:
- https://github.com/meowmeow11118888

## Disclaimer

This tool is for legitimate use only. Ensure you have authorization to scan target domains. The author is not responsible for any misuse or damage caused by using this tool.
