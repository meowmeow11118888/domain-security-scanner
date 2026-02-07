#!/usr/bin/env python3

"""
Domain Security Scanner - Mail Security Configuration Tool

Author: Your Name
Version: 2.2
License: MIT

Changelog v2.2:
- Added SPF qualifier analysis (-all best practice, ~all acceptable, ?all weak)
- Enhanced SPF scoring based on qualifier strength
- Added SPF qualifier warnings and statistics

Changelog v2.1:
- Added DKIM key length verification (2048-bit recommended, 1024-bit weak)
- Enhanced DMARC policy scoring (p=reject best, p=quarantine acceptable, p=none weak)
- Improved security score calculation
- Added detailed warnings for weak configurations
"""

import dns.resolver
import argparse
import csv
import sys
import re
import base64
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import time
from colorama import init, Fore, Style
import concurrent.futures
from dataclasses import dataclass, asdict

# Initialize colorama (Windows terminal color support)
init(autoreset=True)

@dataclass
class DomainResult:
    """Domain scan result data structure"""
    domain: str
    has_mx: bool = False
    mx_count: int = 0
    mx_records: str = ""
    has_spf: bool = False
    spf_record: str = ""
    spf_qualifier: str = ""  # New field: -all, ~all, ?all, etc.
    has_dkim: bool = False
    dkim_selectors: str = ""
    dkim_key_length: str = ""
    dkim_key_strength: str = ""
    has_dmarc: bool = False
    dmarc_record: str = ""
    dmarc_policy: str = ""
    has_a: bool = False
    a_records: str = ""
    mail_enabled: str = "No"
    security_score: int = 0
    config_status: str = ""
    recommendations: str = ""

class DomainScanner:
    """Domain mail security scanner"""

    def __init__(self, max_retries: int = 2, retry_delay: float = 0.5,
                 query_delay: float = 0.3, dkim_selectors: List[str] = None):
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.query_delay = query_delay
        self.dkim_selectors = dkim_selectors or [
            'default', 'google', 'selector1', 'selector2',
            'k1', 'dkim', 's1', 's2'
        ]

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10

    def query_dns_safe(self, domain: str, record_type: str) -> Optional[List]:
        """Safe DNS query with retry mechanism"""
        for attempt in range(self.max_retries + 1):
            try:
                answers = self.resolver.resolve(domain, record_type)
                return list(answers)
            except dns.resolver.NXDOMAIN:
                return None
            except dns.resolver.NoAnswer:
                return None
            except dns.resolver.NoNameservers:
                return None
            except Exception as e:
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    return None
        return None

    def extract_dkim_key_length(self, dkim_record: str) -> Tuple[Optional[int], str]:
        """
        Extract RSA key length from DKIM record
        Returns: (key_length_bits, strength_assessment)
        """
        try:
            # Extract public key from p= parameter
            match = re.search(r'p=([A-Za-z0-9+/=]+)', dkim_record)
            if not match:
                return None, "Unknown"

            key_data = match.group(1)

            # Decode base64
            try:
                decoded = base64.b64decode(key_data)
            except Exception:
                return None, "Unknown"

            # Estimate key length from decoded data length
            # RSA public key in DER format: rough estimation
            key_bytes = len(decoded)

            # Common key sizes and their approximate encoded lengths
            if key_bytes < 200:
                key_bits = 1024
                strength = "Weak"
            elif key_bytes < 400:
                key_bits = 2048
                strength = "Strong"
            elif key_bytes >= 400:
                key_bits = 4096
                strength = "Strong"
            else:
                return None, "Unknown"

            return key_bits, strength

        except Exception:
            return None, "Unknown"

    def extract_spf_qualifier(self, spf_record: str) -> str:
        """
        Extract SPF all mechanism qualifier
        Returns: -all, ~all, ?all, +all, or empty if not found
        """
        # Look for the "all" mechanism with qualifier (dash at end to avoid escaping issues)
        match = re.search(r'([-~+?])all', spf_record)
        if match:
            qualifier = match.group(1)
            if qualifier == '-':
                return "-all"
            elif qualifier == '~':
                return "~all"
            elif qualifier == '?':
                return "?all"
            elif qualifier == '+':
                return "+all"

        # Check if there's just "all" without qualifier (implies +all)
        if re.search(r'\ball\b', spf_record):
            return "+all"

        return ""

    def check_mx(self, domain: str) -> tuple:
        """Check MX records"""
        mx_records = self.query_dns_safe(domain, 'MX')
        if not mx_records:
            return False, 0, ""

        mx_list = []
        for mx in sorted(mx_records, key=lambda x: x.preference):
            mx_list.append(f"{mx.exchange.to_text().rstrip('.')} (Priority: {mx.preference})")

        return True, len(mx_records), "; ".join(mx_list)

    def check_spf(self, domain: str) -> Tuple[bool, str, str]:
        """
        Check SPF records with qualifier analysis
        Returns: (has_spf, spf_record, spf_qualifier)
        """
        txt_records = self.query_dns_safe(domain, 'TXT')
        if not txt_records:
            return False, "", ""

        for record in txt_records:
            txt = record.to_text().strip('"')
            if txt.startswith('v=spf1'):
                qualifier = self.extract_spf_qualifier(txt)
                return True, txt, qualifier

        return False, "", ""

    def check_dkim(self, domain: str) -> Tuple[bool, str, str, str]:
        """
        Check DKIM records with key length analysis
        Returns: (has_dkim, selectors_info, key_lengths, key_strengths)
        """
        found_selectors = []
        key_lengths = []
        key_strengths = []

        for selector in self.dkim_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            txt_records = self.query_dns_safe(dkim_domain, 'TXT')

            if txt_records:
                for record in txt_records:
                    txt = record.to_text().strip('"').replace('" "', '')
                    if 'v=DKIM1' in txt or 'p=' in txt:
                        # Extract key length
                        key_bits, strength = self.extract_dkim_key_length(txt)

                        if key_bits:
                            found_selectors.append(f"{selector} ({key_bits}-bit)")
                            key_lengths.append(f"{selector}:{key_bits}-bit")
                            key_strengths.append(f"{selector}:{strength}")
                        else:
                            found_selectors.append(f"{selector} (unknown length)")
                            key_lengths.append(f"{selector}:Unknown")
                            key_strengths.append(f"{selector}:Unknown")
                        break

        if found_selectors:
            return (True, 
                    "; ".join(found_selectors),
                    "; ".join(key_lengths),
                    "; ".join(key_strengths))

        return False, "", "", ""

    def check_dmarc(self, domain: str) -> tuple:
        """Check DMARC records"""
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = self.query_dns_safe(dmarc_domain, 'TXT')

        if not txt_records:
            return False, "", ""

        for record in txt_records:
            txt = record.to_text().strip('"').replace('" "', '')
            if txt.startswith('v=DMARC1'):
                # Extract policy
                policy = ""
                if 'p=' in txt:
                    match = re.search(r'p=([^;]+)', txt)
                    if match:
                        policy = match.group(1).strip()

                return True, txt, policy

        return False, "", ""

    def check_a(self, domain: str) -> tuple:
        """Check A records"""
        a_records = self.query_dns_safe(domain, 'A')
        if not a_records:
            return False, "Unable to resolve"

        ips = [record.to_text() for record in a_records]
        return True, ", ".join(ips)

    def calculate_score(self, result: DomainResult) -> int:
        """
        Calculate security score with enhanced evaluation
        Total: 100 points
        """
        score = 0

        # MX record: 20 points
        if result.has_mx:
            score += 20

        # SPF record: up to 30 points (with qualifier bonus)
        if result.has_spf:
            # Base score for having SPF
            score += 25

            # Qualifier bonus
            if result.spf_qualifier == "-all":
                # Hard fail (best practice): full 5 bonus points
                score += 5
            elif result.spf_qualifier == "~all":
                # Soft fail (acceptable): 3 bonus points
                score += 3
            elif result.spf_qualifier in ["?all", "+all", ""]:
                # Neutral/Pass/None (weak): 0 bonus points
                score += 0

        # DKIM record: up to 25 points
        if result.has_dkim:
            # Base score for having DKIM
            score += 15

            # Additional points for strong keys
            if "Weak" in result.dkim_key_strength:
                # 1024-bit keys: only 5 more points (total 20/25)
                score += 5
            elif "Strong" in result.dkim_key_strength:
                # 2048-bit or higher: full 10 more points (total 25/25)
                score += 10
            elif "Unknown" in result.dkim_key_strength:
                # Unknown key length: 7 points (total 22/25)
                score += 7

        # DMARC record: up to 25 points
        if result.has_dmarc:
            if result.dmarc_policy == 'reject':
                # Best practice: full 25 points
                score += 25
            elif result.dmarc_policy == 'quarantine':
                # Acceptable: 20 points
                score += 20
            elif result.dmarc_policy == 'none':
                # Monitoring only: 10 points
                score += 10
            else:
                # Unknown policy: 5 points
                score += 5

        return min(score, 100)

    def assess_config(self, result: DomainResult) -> tuple:
        """Assess configuration status and recommendations with enhanced checks"""
        recommendations = []

        if not result.has_mx and not result.has_spf:
            result.mail_enabled = "No"
            return "No Mail Configuration", ""

        result.mail_enabled = "Yes"

        # Check SPF qualifier
        if result.has_spf:
            if result.spf_qualifier == "~all":
                recommendations.append("[NOTICE] SPF uses ~all (soft fail), consider upgrading to -all (hard fail)")
            elif result.spf_qualifier in ["?all", "+all"]:
                recommendations.append("[WARNING] SPF uses weak qualifier, must change to -all for proper protection")
            elif not result.spf_qualifier:
                recommendations.append("[WARNING] SPF missing 'all' mechanism, add -all for best protection")

        # Check DKIM key strength
        if result.has_dkim and "Weak" in result.dkim_key_strength:
            recommendations.append("[WARNING] DKIM uses weak 1024-bit key, upgrade to 2048-bit")

        # Check DMARC policy
        if result.has_dmarc:
            if result.dmarc_policy == 'none':
                recommendations.append("[WARNING] DMARC policy is 'none' (monitoring only), upgrade to 'quarantine' or 'reject'")
            elif result.dmarc_policy == 'quarantine':
                recommendations.append("Consider upgrading DMARC policy to p=reject for maximum protection")

        # Determine configuration status
        if (result.has_mx and result.has_spf and result.has_dkim and 
            result.has_dmarc and result.dmarc_policy == 'reject' and
            "Strong" in result.dkim_key_strength and result.spf_qualifier == "-all"):
            status = "Full Protection (Best Practice)"
        elif (result.has_mx and result.has_spf and result.has_dkim and 
              result.has_dmarc and result.dmarc_policy in ['reject', 'quarantine']):
            if "Weak" in result.dkim_key_strength:
                status = "Good Protection (Weak DKIM Key)"
            elif result.spf_qualifier in ["?all", "+all", ""]:
                status = "Good Protection (Weak SPF)"
            else:
                status = "Full Protection"
        elif result.has_mx and result.has_spf and result.has_dmarc:
            status = "Good Protection (Missing DKIM)"
            recommendations.append("Recommend setting up DKIM with 2048-bit key")
        elif result.has_mx and result.has_spf and result.has_dkim:
            status = "Good Protection (Missing DMARC)"
            recommendations.append("Recommend adding DMARC record with p=quarantine or p=reject")
        elif result.has_mx and result.has_spf:
            status = "Basic Protection"
            recommendations.append("Recommend adding DMARC record with p=quarantine or p=reject")
            recommendations.append("Recommend setting up DKIM with 2048-bit key")
        elif result.has_mx and not result.has_spf:
            status = "High Risk (Missing SPF)"
            recommendations.append("[URGENT] Must add SPF record to prevent email spoofing")
            recommendations.append("Recommend setting up DKIM with 2048-bit key and DMARC")
        elif not result.has_mx and result.has_spf:
            status = "Abnormal Configuration (SPF only, no MX)"
            recommendations.append("Check for misconfiguration or external mail service usage")
        else:
            status = "No Mail Configuration"

        return status, " | ".join(recommendations)

    def scan_domain(self, domain: str) -> DomainResult:
        """Scan a single domain"""
        result = DomainResult(domain=domain.strip())

        # Check all records
        result.has_a, result.a_records = self.check_a(domain)
        result.has_mx, result.mx_count, result.mx_records = self.check_mx(domain)

        # Enhanced SPF check with qualifier
        result.has_spf, result.spf_record, result.spf_qualifier = self.check_spf(domain)

        # Enhanced DKIM check with key length
        (result.has_dkim, result.dkim_selectors, 
         result.dkim_key_length, result.dkim_key_strength) = self.check_dkim(domain)

        result.has_dmarc, result.dmarc_record, result.dmarc_policy = self.check_dmarc(domain)

        # Calculate score and assessment
        result.security_score = self.calculate_score(result)
        result.config_status, result.recommendations = self.assess_config(result)

        time.sleep(self.query_delay)
        return result

class ReportGenerator:
    """Report generator"""

    @staticmethod
    def print_summary(results: List[DomainResult]):
        """Print summary statistics"""
        total = len(results)
        mail_enabled = sum(1 for r in results if r.mail_enabled == "Yes")
        has_spf = sum(1 for r in results if r.has_spf)
        has_dkim = sum(1 for r in results if r.has_dkim)
        has_dmarc = sum(1 for r in results if r.has_dmarc)
        full_protection = sum(1 for r in results if "Full Protection" in r.config_status)
        high_risk = sum(1 for r in results if "High Risk" in r.config_status)

        # SPF qualifier statistics
        spf_hardfail = sum(1 for r in results if r.spf_qualifier == "-all")
        spf_softfail = sum(1 for r in results if r.spf_qualifier == "~all")
        spf_weak = sum(1 for r in results if r.has_spf and r.spf_qualifier in ["?all", "+all", ""])

        # DKIM key strength statistics
        weak_dkim = sum(1 for r in results if r.has_dkim and "Weak" in r.dkim_key_strength)
        strong_dkim = sum(1 for r in results if r.has_dkim and "Strong" in r.dkim_key_strength)

        # DMARC policy statistics
        dmarc_reject = sum(1 for r in results if r.dmarc_policy == 'reject')
        dmarc_quarantine = sum(1 for r in results if r.dmarc_policy == 'quarantine')
        dmarc_none = sum(1 for r in results if r.dmarc_policy == 'none')

        avg_score = sum(r.security_score for r in results) / total if total > 0 else 0

        print(f"\n{Fore.GREEN}======================================")
        print(f"{Fore.GREEN}Scan Complete - Summary")
        print(f"{Fore.GREEN}======================================\n")
        print(f"Total Domains: {total}")
        print(f"Mail Enabled: {mail_enabled} ({mail_enabled/total*100:.1f}%)")

        print(f"\n{Fore.CYAN}Email Authentication:")
        print(f"  SPF Protected: {has_spf} ({has_spf/total*100:.1f}%)")
        if has_spf > 0:
            print(f"    - {Fore.GREEN}-all (Hard Fail): {spf_hardfail} [Best Practice]")
            print(f"    - {Fore.CYAN}~all (Soft Fail): {spf_softfail} [Acceptable]")
            if spf_weak > 0:
                print(f"    - {Fore.YELLOW}?all/+all/none: {spf_weak} [Weak - Upgrade Recommended]")

        print(f"  DKIM Protected: {has_dkim} ({has_dkim/total*100:.1f}%)")
        if has_dkim > 0:
            print(f"    - {Fore.GREEN}Strong Keys (2048-bit+): {strong_dkim}")
            if weak_dkim > 0:
                print(f"    - {Fore.YELLOW}Weak Keys (1024-bit): {weak_dkim} [Upgrade Recommended]")

        print(f"  DMARC Enabled: {has_dmarc} ({has_dmarc/total*100:.1f}%)")
        if has_dmarc > 0:
            print(f"    - {Fore.GREEN}p=reject: {dmarc_reject}")
            print(f"    - {Fore.CYAN}p=quarantine: {dmarc_quarantine}")
            if dmarc_none > 0:
                print(f"    - {Fore.YELLOW}p=none: {dmarc_none} [Monitoring Only]")

        print(f"\n{Fore.CYAN}Overall Status:")
        print(f"  {Fore.GREEN}Full Protection: {full_protection}")
        print(f"  {Fore.RED}High Risk Domains: {high_risk}")

        score_color = Fore.GREEN if avg_score >= 70 else Fore.YELLOW if avg_score >= 40 else Fore.RED
        print(f"  {score_color}Average Security Score: {avg_score:.1f} / 100\n")

    @staticmethod
    def print_config_groups(results: List[DomainResult]):
        """Print configuration status groups"""
        print(f"\n{Fore.YELLOW}======================================")
        print(f"{Fore.YELLOW}Configuration Status Groups")
        print(f"{Fore.YELLOW}======================================\n")

        from collections import Counter
        status_count = Counter(r.config_status for r in results)

        for status, count in status_count.most_common():
            if "Best Practice" in status:
                color = Fore.GREEN
            elif "Full Protection" in status:
                color = Fore.GREEN
            elif "High Risk" in status:
                color = Fore.RED
            elif "Good Protection" in status:
                if "Weak" in status:
                    color = Fore.YELLOW
                else:
                    color = Fore.CYAN
            elif "Basic" in status:
                color = Fore.YELLOW
            else:
                color = Fore.WHITE

            print(f"{color}{status}: {count} domains")

    @staticmethod
    def print_score_distribution(results: List[DomainResult]):
        """Print score distribution"""
        print(f"\n{Fore.CYAN}======================================")
        print(f"{Fore.CYAN}Security Score Distribution")
        print(f"{Fore.CYAN}======================================\n")

        ranges = {
            "90-100 (Excellent)": sum(1 for r in results if r.security_score >= 90),
            "70-89 (Good)": sum(1 for r in results if 70 <= r.security_score < 90),
            "50-69 (Fair)": sum(1 for r in results if 50 <= r.security_score < 70),
            "30-49 (Needs Improvement)": sum(1 for r in results if 30 <= r.security_score < 50),
            "0-29 (Critical)": sum(1 for r in results if r.security_score < 30),
        }

        colors = {
            "90-100 (Excellent)": Fore.GREEN,
            "70-89 (Good)": Fore.CYAN,
            "50-69 (Fair)": Fore.YELLOW,
            "30-49 (Needs Improvement)": Fore.MAGENTA,
            "0-29 (Critical)": Fore.RED,
        }

        for range_name, count in ranges.items():
            print(f"{colors[range_name]}{range_name}: {count} domains")

    @staticmethod
    def print_high_risk(results: List[DomainResult]):
        """Print high risk domains and warnings"""
        high_risk = [r for r in results if "High Risk" in r.config_status]
        weak_spf = [r for r in results if r.has_spf and r.spf_qualifier in ["?all", "+all", ""]]
        weak_keys = [r for r in results if r.has_dkim and "Weak" in r.dkim_key_strength]
        weak_dmarc = [r for r in results if r.has_dmarc and r.dmarc_policy == 'none']

        if high_risk:
            print(f"\n{Fore.RED}======================================")
            print(f"{Fore.RED}High Risk Domains (Immediate Action Required)")
            print(f"{Fore.RED}======================================\n")
            print(f"{'Domain':<35} {'Score':<8} {'Issue'}")
            print("-" * 85)

            for r in high_risk:
                print(f"{r.domain:<35} {r.security_score:<8} Missing SPF")

        if weak_spf:
            print(f"\n{Fore.YELLOW}======================================")
            print(f"{Fore.YELLOW}Weak SPF Qualifiers (Upgrade Recommended)")
            print(f"{Fore.YELLOW}======================================\n")
            print(f"{'Domain':<35} {'Qualifier':<15} {'Recommendation'}")
            print("-" * 85)

            for r in weak_spf:
                qualifier_display = r.spf_qualifier if r.spf_qualifier else "none"
                print(f"{r.domain:<35} {qualifier_display:<15} Change to -all (hard fail)")

        if weak_keys:
            print(f"\n{Fore.YELLOW}======================================")
            print(f"{Fore.YELLOW}Weak DKIM Keys (Upgrade Recommended)")
            print(f"{Fore.YELLOW}======================================\n")
            print(f"{'Domain':<35} {'Key Length':<15} {'Status'}")
            print("-" * 85)

            for r in weak_keys:
                print(f"{r.domain:<35} 1024-bit        Weak - Upgrade to 2048-bit")

        if weak_dmarc:
            print(f"\n{Fore.YELLOW}======================================")
            print(f"{Fore.YELLOW}Weak DMARC Policy (Monitoring Only)")
            print(f"{Fore.YELLOW}======================================\n")
            print(f"{'Domain':<35} {'Policy':<15} {'Recommendation'}")
            print("-" * 85)

            for r in weak_dmarc:
                print(f"{r.domain:<35} p=none          Upgrade to p=quarantine or p=reject")

    @staticmethod
    def save_csv(results: List[DomainResult], output_path: Path):
        """Save CSV report with enhanced details"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_file = output_path / f"domain_security_report_{timestamp}.csv"

        with open(csv_file, 'w', newline='', encoding='utf-8-sig') as f:
            fieldnames = [
                'Domain', 'MX Record', 'MX Count', 'MX Details',
                'SPF Record', 'SPF Content', 'SPF Qualifier',
                'DKIM Record', 'DKIM Selectors', 'DKIM Key Length', 'DKIM Key Strength',
                'DMARC Record', 'DMARC Content', 'DMARC Policy',
                'A Record', 'IP Addresses',
                'Mail Enabled', 'Security Score', 'Config Status', 'Recommendations'
            ]

            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for r in results:
                writer.writerow({
                    'Domain': r.domain,
                    'MX Record': 'Yes' if r.has_mx else 'No',
                    'MX Count': r.mx_count,
                    'MX Details': r.mx_records,
                    'SPF Record': 'Yes' if r.has_spf else 'No',
                    'SPF Content': r.spf_record,
                    'SPF Qualifier': r.spf_qualifier,
                    'DKIM Record': 'Yes' if r.has_dkim else 'No',
                    'DKIM Selectors': r.dkim_selectors,
                    'DKIM Key Length': r.dkim_key_length,
                    'DKIM Key Strength': r.dkim_key_strength,
                    'DMARC Record': 'Yes' if r.has_dmarc else 'No',
                    'DMARC Content': r.dmarc_record,
                    'DMARC Policy': r.dmarc_policy,
                    'A Record': 'Yes' if r.has_a else 'No',
                    'IP Addresses': r.a_records,
                    'Mail Enabled': r.mail_enabled,
                    'Security Score': r.security_score,
                    'Config Status': r.config_status,
                    'Recommendations': r.recommendations
                })

        print(f"\n{Fore.GREEN}Detailed report exported to: {csv_file}")
        return csv_file

def main():
    parser = argparse.ArgumentParser(
        description='Domain Security Scanner v2.2 - Enhanced SPF, DKIM, and DMARC analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f domains.txt
  %(prog)s -d example.com test.org
  %(prog)s -f domains.txt -o ./reports --max-retries 3
  %(prog)s -f domains.txt --dkim-selectors default,google,amazonses

New in v2.2:
  - SPF qualifier verification (-all recommended, ~all acceptable, ?all/+all weak)
  - Enhanced SPF scoring based on qualifier strength

New in v2.1:
  - DKIM key length verification (2048-bit recommended)
  - Enhanced DMARC policy evaluation (p=reject best practice)
  - Improved security scoring
"""
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', type=str, help='Domain list file (one domain per line)')
    group.add_argument('-d', '--domains', nargs='+', help='Specify domains directly')

    parser.add_argument('-o', '--output', type=str, default='.',
                        help='Report output directory (default: current directory)')
    parser.add_argument('--max-retries', type=int, default=2,
                        help='DNS query retry count on failure (default: 2)')
    parser.add_argument('--retry-delay', type=float, default=0.5,
                        help='Retry delay in seconds (default: 0.5)')
    parser.add_argument('--query-delay', type=float, default=0.3,
                        help='Delay between domain queries in seconds (default: 0.3)')
    parser.add_argument('--dkim-selectors', type=str,
                        default='default,google,selector1,selector2,k1,dkim,s1,s2',
                        help='DKIM selectors (comma-separated)')
    parser.add_argument('--parallel', type=int, default=1,
                        help='Number of parallel scan threads (default: 1, max recommended: 5)')

    args = parser.parse_args()

    # Read domain list
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File not found {args.file}")
            sys.exit(1)
    else:
        domains = args.domains

    # Create output directory
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)

    # Initialize scanner
    dkim_selectors = args.dkim_selectors.split(',')
    scanner = DomainScanner(
        max_retries=args.max_retries,
        retry_delay=args.retry_delay,
        query_delay=args.query_delay,
        dkim_selectors=dkim_selectors
    )

    # Start scanning
    print(f"{Fore.GREEN}======================================")
    print(f"{Fore.GREEN}Domain Security Scanner v2.2")
    print(f"{Fore.GREEN}======================================")
    print(f"{Fore.CYAN}Scanning {len(domains)} domains")
    print(f"{Fore.CYAN}DKIM Selectors: {args.dkim_selectors}")
    print(f"{Fore.CYAN}Enhanced: SPF qualifier + DKIM key + DMARC policy analysis")
    print(f"{Fore.GREEN}======================================\n")

    results = []

    if args.parallel > 1:
        # Parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as executor:
            future_to_domain = {executor.submit(scanner.scan_domain, domain): domain 
                                for domain in domains}
            for i, future in enumerate(concurrent.futures.as_completed(future_to_domain), 1):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    results.append(result)
                    progress = i / len(domains) * 100
                    print(f"{Fore.CYAN}[{i}/{len(domains)}] ({progress:.1f}%) Completed {domain}")
                except Exception as e:
                    print(f"{Fore.RED}[{i}/{len(domains)}] Error {domain}: {e}")
    else:
        # Sequential scanning
        for i, domain in enumerate(domains, 1):
            progress = i / len(domains) * 100
            print(f"{Fore.CYAN}[{i}/{len(domains)}] ({progress:.1f}%) Checking {domain} ...")
            try:
                result = scanner.scan_domain(domain)
                results.append(result)
            except Exception as e:
                print(f"{Fore.RED}Error: {domain} - {e}")

    # Generate reports
    if results:
        ReportGenerator.print_summary(results)
        ReportGenerator.print_config_groups(results)
        ReportGenerator.print_score_distribution(results)
        ReportGenerator.print_high_risk(results)
        ReportGenerator.save_csv(results, output_path)

        print(f"\n{Fore.GREEN}======================================")
        print(f"{Fore.GREEN}Scan Complete!")
        print(f"{Fore.GREEN}======================================\n")
    else:
        print(f"{Fore.RED}No domains successfully scanned")
        sys.exit(1)

if __name__ == '__main__':
    main()
