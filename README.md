# Domain Security Scanner

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-2.1-brightgreen.svg)

Batch check domain mail security configuration including MX, SPF, DKIM, DMARC records with **enhanced DKIM key strength analysis** and **DMARC policy evaluation**. Get detailed risk assessment and remediation recommendations.

## ✨ What's New in v2.1

- 🔑 **DKIM Key Length Analysis**: Detect 1024-bit (weak) vs 2048-bit (strong) RSA keys
- 🛡️ **Enhanced DMARC Evaluation**: Detailed scoring for p=reject/quarantine/none policies
- ⚠️ **Smart Warnings**: Automatic alerts for weak configurations
- 📊 **Improved Scoring**: More accurate security assessment based on key strength and policy strictness

## Features

- ✅ **Batch Scanning**: Check dozens to hundreds of domains at once
- 🔍 **Complete Check**: Covers MX, SPF, DKIM (with key analysis), DMARC, and A records
- 🔑 **DKIM Key Strength**: Validates RSA key length (2048-bit recommended, 1024-bit flagged as weak)
- 🛡️ **DMARC Policy Check**: Evaluates p=reject (best), p=quarantine (acceptable), p=none (weak)
- 📊 **Smart Scoring**: 0-100 security score with enhanced evaluation logic
- 🎯 **Risk Classification**: Auto-categorize with detailed warnings
- 📝 **Detailed Reports**: Comprehensive CSV reports with key strength and policy analysis
- 💡 **Fix Recommendations**: Specific guidance for weak keys and policies
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
git clone https://github.com/meowmeow11118888/domain-security-scanner.git
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

The script generates a comprehensive CSV report:

### Detailed Security Report (CSV)
`domain_security_report_YYYYMMDD_HHMMSS.csv`

Contains complete check results for each domain including:
- All DNS record details (MX, SPF, DKIM, DMARC, A)
- **DKIM Key Length** (e.g., 1024-bit, 2048-bit)
- **DKIM Key Strength** (Strong/Weak/Unknown)
- **DMARC Policy** (reject/quarantine/none)
- Security score (0-100)
- Configuration status
- Specific recommendations

Can be opened in Excel, Google Sheets, or any spreadsheet application.

## Enhanced Security Scoring (v2.1)

### Total: 100 points

| Component | Max Points | Details |
|-----------|------------|---------|
| **MX Record** | 20 points | Has mail server configured |
| **SPF Record** | 30 points | Sender Policy Framework configured |
| **DKIM Record** | 25 points | **Enhanced scoring based on key strength:** |
| | | • 2048-bit or higher: **25 points** (full score) |
| | | • 1024-bit key: **20 points** (weak, -5 penalty) |
| | | • Unknown key length: **22 points** |
| **DMARC Record** | 25 points | **Policy-based scoring:** |
| | | • p=reject: **25 points** (best practice) |
| | | • p=quarantine: **20 points** (acceptable) |
| | | • p=none: **10 points** (monitoring only) |

### Score Grades

- **90-100**: Excellent (Best Practice - Strong keys + strict policies)
- **70-89**: Good (Minor improvements recommended)
- **50-69**: Fair (Notable security gaps)
- **30-49**: Needs Improvement (Significant risks)
- **0-29**: Critical (Immediate action required)

## Configuration Status Explained

| Status | Description | Security Level |
|--------|-------------|----------------|
| **Full Protection (Best Practice)** | MX + SPF + DKIM (2048-bit) + DMARC (p=reject) | 🟢 Excellent |
| **Full Protection** | MX + SPF + DKIM + DMARC (p=reject or p=quarantine) | 🟢 Good |
| **Good Protection (Weak DKIM Key)** | Complete setup but DKIM uses 1024-bit key | 🟡 Needs Upgrade |
| **Good Protection (Missing DKIM)** | MX + SPF + DMARC | 🟡 Good |
| **Good Protection (Missing DMARC)** | MX + SPF + DKIM | 🟡 Add DMARC |
| **Basic Protection** | MX + SPF only | 🟡 Basic |
| **High Risk (Missing SPF)** | MX without SPF - vulnerable to spoofing | 🔴 Urgent |
| **Abnormal Configuration** | SPF without MX | 🟠 Review |
| **No Mail Configuration** | No mail-related records | ⚪ N/A |

## DKIM Key Strength Guidelines

### Why Key Length Matters

- **1024-bit RSA keys**: Increasingly vulnerable to modern computing attacks
- **2048-bit RSA keys**: Current industry standard (recommended until ~2030)
- **4096-bit RSA keys**: Maximum security (some systems may have compatibility issues)

### Current Recommendations

| Key Size | Security Level | Recommendation |
|----------|----------------|----------------|
| 1024-bit | 🔴 Weak | **Upgrade immediately** - Vulnerable to attacks |
| 2048-bit | 🟢 Strong | **Recommended** - Industry standard |
| 4096-bit | 🟢 Very Strong | Optional - May have size limitations |

### How the Tool Detects Key Length

The scanner analyzes the public key in DKIM TXT records:
- Decodes the base64-encoded public key (p= parameter)
- Estimates RSA modulus length from decoded data
- Flags 1024-bit keys with warnings and score penalties

## DMARC Policy Guidelines

### Policy Levels

| Policy | Meaning | Use Case | Score |
|--------|---------|----------|-------|
| **p=reject** | Reject unauthenticated emails | 🟢 Production (Best Practice) | 25/25 pts |
| **p=quarantine** | Mark as spam/suspicious | 🟡 Transition phase | 20/25 pts |
| **p=none** | Monitor only, take no action | 🟠 Testing/Learning | 10/25 pts |

### Recommended Approach

1. **Start with p=none**: Monitor DMARC reports for 2-4 weeks
2. **Move to p=quarantine**: Test impact on legitimate email flow
3. **Enforce with p=reject**: Maximum protection once confident

```
# Phase 1: Monitoring (Start here)
v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com

# Phase 2: Gradual enforcement
v=DMARC1; p=quarantine; pct=10; rua=mailto:dmarc-reports@yourdomain.com

# Phase 3: Full protection (Goal)
v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@yourdomain.com
```

## Console Output Examples

### Summary Report
```
======================================
Scan Complete - Summary
======================================

Total Domains: 50
Mail Enabled: 45 (90.0%)

Email Authentication:
  SPF Protected: 43 (86.0%)
  DKIM Protected: 38 (76.0%)
    - Strong Keys (2048-bit+): 32
    - Weak Keys (1024-bit): 6 [Upgrade Recommended]
  DMARC Enabled: 35 (70.0%)
    - p=reject: 20
    - p=quarantine: 10
    - p=none: 5 [Monitoring Only]

Overall Status:
  Full Protection: 28
  High Risk Domains: 2
  Average Security Score: 76.8 / 100
```

### Warning Sections

The tool displays three types of warnings:

1. **High Risk Domains**: Missing SPF (immediate threat)
2. **Weak DKIM Keys**: 1024-bit keys needing upgrade
3. **Weak DMARC Policy**: p=none policies in production

## Usage Examples

### Example 1: Quick Security Audit
```bash
python domain_security_scanner.py -d google.com microsoft.com apple.com
```

### Example 2: Enterprise Domain Portfolio Scan
```bash
python domain_security_scanner.py -f company_domains.txt -o ./audit_reports
```

### Example 3: Fast Parallel Scan
```bash
python domain_security_scanner.py -f large_list.txt --parallel 5 --query-delay 0.5
```

### Example 4: Focus on Google Workspace DKIM
```bash
python domain_security_scanner.py -f domains.txt --dkim-selectors google,googlemail
```

## Remediation Guide

### Upgrade Weak DKIM Keys (1024-bit → 2048-bit)

#### Google Workspace
1. Admin Console → Apps → Google Workspace → Gmail
2. Authenticate email → Generate new DKIM record
3. Select **2048-bit key length**
4. Update DNS with new TXT record

#### Microsoft 365
1. Exchange Admin Center → Protection → DKIM
2. Rotate keys → Choose 2048-bit
3. Update DNS records

#### Generic Steps (Any Provider)
```bash
# Generate 2048-bit DKIM key (using openssl)
openssl genrsa -out dkim_private.pem 2048
openssl rsa -in dkim_private.pem -pubout -outform der 2>/dev/null | openssl base64 -A
```

### Strengthen DMARC Policy

#### Step 1: Add DMARC (if missing)
```
v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com; pct=100
```

#### Step 2: Monitor Reports (2-4 weeks)
- Review aggregate reports (rua)
- Identify legitimate senders
- Fix SPF/DKIM for authorized senders

#### Step 3: Move to Quarantine
```
v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@yourdomain.com
```

#### Step 4: Enforce with Reject
```
v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@yourdomain.com; adkim=s; aspf=s
```

### SPF Record Examples

**Basic setup:**
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

## Performance Notes

### Scan Speed
- **Sequential scan** (default): ~1-3 seconds per domain
  - 100 domains: 3-5 minutes
- **Parallel scan** (`--parallel 5`): 3-4x faster
  - 100 domains: 1-2 minutes

### Recommended Settings
- Less than 50 domains: Default sequential scan
- 50-200 domains: `--parallel 3`
- 200+ domains: `--parallel 5` (avoid DNS rate limits)

## Best Practices Checklist

### Email Security Baseline
- [ ] MX records configured
- [ ] SPF record with proper includes
- [ ] DKIM with **2048-bit keys**
- [ ] DMARC with **p=quarantine** or **p=reject**
- [ ] Regular monitoring of DMARC reports

### Scoring 90+ Points
To achieve "Excellent" rating:
1. ✅ Configure all four records (MX, SPF, DKIM, DMARC)
2. ✅ Use 2048-bit or higher DKIM keys
3. ✅ Set DMARC policy to p=reject
4. ✅ Regular audits (quarterly recommended)

## Use Cases

- 🏢 **Enterprise IT**: Audit multiple subsidiary domains
- 🔒 **Security Teams**: Identify vulnerable configurations
- 🌐 **MSPs**: Manage client email security compliance
- 📊 **Compliance**: Meet email authentication standards (DMARC.org, IRS, etc.)
- 🚀 **Migration**: Verify configuration after mail server changes
- 🐧 **DevOps**: Integrate into CI/CD pipelines for automated checks

## Changelog

### v2.1 (2026-02-07)
- ✨ **NEW**: DKIM RSA key length analysis (1024 vs 2048-bit)
- ✨ **NEW**: Enhanced DMARC policy scoring (reject/quarantine/none)
- 🔧 **IMPROVED**: More granular security scoring
- 🔧 **IMPROVED**: Smart warnings for weak configurations
- 📝 **ADDED**: Key strength and policy columns in CSV
- 📝 **ADDED**: Separate warning sections in console output

### v2.0 (2026-02-04)
- ✨ Python version initial release
- ✨ DKIM record checking
- ✨ Security score calculation (0-100)
- ✨ Command-line argument support
- ✨ Parallel scanning support
- ✨ Cross-platform support

## Related Resources

### Standards & RFCs
- [RFC 7208 - SPF](https://tools.ietf.org/html/rfc7208)
- [RFC 6376 - DKIM](https://tools.ietf.org/html/rfc6376)
- [RFC 7489 - DMARC](https://tools.ietf.org/html/rfc7489)

### Tools & Services
- [MXToolbox](https://mxtoolbox.com/) - Online DNS checking
- [dmarcian](https://dmarcian.com/) - DMARC analyzer
- [Google Admin Toolbox](https://toolbox.googleapps.com/apps/checkmx/) - MX checker

### Documentation
- [dnspython](https://dnspython.readthedocs.io/) - Library documentation
- [DMARC.org](https://dmarc.org/) - Official DMARC specification

## Security Considerations

### What This Tool Does
✅ Checks DNS records (public information)
✅ Analyzes email authentication configuration
✅ Provides security recommendations

### What This Tool Does NOT Do
❌ Does not send emails or test actual mail flow
❌ Does not access email servers or accounts
❌ Does not bypass any security measures

### Responsible Use
- Only scan domains you own or have permission to audit
- Respect DNS rate limits (use --query-delay)
- Do not use for unauthorized reconnaissance

## License
MIT License - See [LICENSE](LICENSE) file for details

## Contributing
Issues and Pull Requests are welcome!

### Development Guidelines
- Follow PEP 8 coding style
- Add unit tests for new features
- Update documentation
- Test across different email providers

## Author
- https://github.com/meowmeow11118888

## Disclaimer

This tool is provided "as is" for legitimate security assessment purposes. The author is not responsible for:
- Misuse or unauthorized scanning
- Decisions made based on scan results
- Any damages resulting from tool usage

Always verify critical security configurations with your email service provider.
