#!/usr/bin/env python3

"""
Domain Security Scanner - Mail Security Configuration Tool

Author: Your Name
Version: 2.0
License: MIT
"""

import dns.resolver
import argparse
import csv
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
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
    has_dkim: bool = False
    dkim_selectors: str = ""
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

    def check_mx(self, domain: str) -> tuple:
        """Check MX records"""
        mx_records = self.query_dns_safe(domain, 'MX')
        if not mx_records:
            return False, 0, ""

        mx_list = []
        for mx in sorted(mx_records, key=lambda x: x.preference):
            mx_list.append(f"{mx.exchange.to_text().rstrip('.')} (Priority: {mx.preference})")

        return True, len(mx_records), "; ".join(mx_list)

    def check_spf(self, domain: str) -> tuple:
        """Check SPF records"""
        txt_records = self.query_dns_safe(domain, 'TXT')
        if not txt_records:
            return False, ""

        for record in txt_records:
            txt = record.to_text().strip('"')
            if txt.startswith('v=spf1'):
                return True, txt

        return False, ""

    def check_dkim(self, domain: str) -> tuple:
        """Check DKIM records"""
        found_selectors = []

        for selector in self.dkim_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            txt_records = self.query_dns_safe(dkim_domain, 'TXT')

            if txt_records:
                for record in txt_records:
                    txt = record.to_text().strip('"').replace('" "', '')
                    if 'v=DKIM1' in txt or 'p=' in txt:
                        found_selectors.append(f"{selector} ({txt[:50]}...)")
                        break

        if found_selectors:
            return True, "; ".join(found_selectors)
        return False, ""

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
                    import re
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
        """Calculate security score"""
        score = 0
        if result.has_mx:
            score += 20
        if result.has_spf:
            score += 30
        if result.has_dkim:
            score += 25
        if result.has_dmarc:
            score += 25
            if result.dmarc_policy == 'reject':
                score += 10
            elif result.dmarc_policy == 'quarantine':
                score += 5

        return min(score, 100)

    def assess_config(self, result: DomainResult) -> tuple:
        """Assess configuration status and recommendations"""
        recommendations = []

        if not result.has_mx and not result.has_spf:
            result.mail_enabled = "No"
            return "No Mail Configuration", ""

        result.mail_enabled = "Yes"

        # Determine configuration status
        if (result.has_mx and result.has_spf and result.has_dkim and 
            result.has_dmarc and result.dmarc_policy == 'reject'):
            status = "Full Protection (Best Practice)"
        elif result.has_mx and result.has_spf and result.has_dkim and result.has_dmarc:
            status = "Full Protection"
            if result.dmarc_policy != 'reject':
                recommendations.append("Consider upgrading DMARC policy to p=reject")
        elif result.has_mx and result.has_spf and result.has_dmarc:
            status = "Good Protection (Missing DKIM)"
            recommendations.append("Recommend setting up DKIM for enhanced authentication")
        elif result.has_mx and result.has_spf:
            status = "Basic Protection"
            recommendations.append("Recommend adding DMARC record")
            recommendations.append("Recommend setting up DKIM authentication")
        elif result.has_mx and not result.has_spf:
            status = "High Risk (Missing SPF)"
            recommendations.append("[URGENT] Must add SPF record to prevent email spoofing")
            recommendations.append("Recommend setting up both DKIM and DMARC")
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
        result.has_spf, result.spf_record = self.check_spf(domain)
        result.has_dkim, result.dkim_selectors = self.check_dkim(domain)
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
        avg_score = sum(r.security_score for r in results) / total if total > 0 else 0

        print(f"\n{Fore.GREEN}======================================")
        print(f"{Fore.GREEN}Scan Complete - Summary")
        print(f"{Fore.GREEN}======================================\n")
        print(f"Total Domains: {total}")
        print(f"Mail Enabled: {mail_enabled} ({mail_enabled/total*100:.1f}%)")
        print(f"SPF Protected: {has_spf} ({has_spf/total*100:.1f}%)")
        print(f"DKIM Protected: {has_dkim} ({has_dkim/total*100:.1f}%)")
        print(f"DMARC Enabled: {has_dmarc} ({has_dmarc/total*100:.1f}%)")
        print(f"{Fore.GREEN}Full Protection: {full_protection}")
        print(f"{Fore.RED}High Risk Domains: {high_risk}")

        score_color = Fore.GREEN if avg_score >= 70 else Fore.YELLOW if avg_score >= 40 else Fore.RED
        print(f"{score_color}Average Security Score: {avg_score:.1f} / 100\n")

    @staticmethod
    def print_config_groups(results: List[DomainResult]):
        """Print configuration status groups"""
        print(f"\n{Fore.YELLOW}======================================")
        print(f"{Fore.YELLOW}Configuration Status Groups")
        print(f"{Fore.YELLOW}======================================\n")

        from collections import Counter
        status_count = Counter(r.config_status for r in results)

        for status, count in status_count.most_common():
            if "Full" in status:
                color = Fore.GREEN
            elif "High Risk" in status:
                color = Fore.RED
            elif "Good" in status:
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
        """Print high risk domains"""
        high_risk = [r for r in results if "High Risk" in r.config_status]

        if high_risk:
            print(f"\n{Fore.RED}======================================")
            print(f"{Fore.RED}High Risk Domains (Immediate Action Required)")
            print(f"{Fore.RED}======================================\n")
            print(f"{'Domain':<30} {'Score':<10} {'Recommendations'}")
            print("-" * 80)

            for r in high_risk:
                print(f"{r.domain:<30} {r.security_score:<10} {r.recommendations[:40]}")

    @staticmethod
    def save_csv(results: List[DomainResult], output_path: Path):
        """Save CSV report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_file = output_path / f"domain_security_report_{timestamp}.csv"

        with open(csv_file, 'w', newline='', encoding='utf-8-sig') as f:
            fieldnames = [
                'Domain', 'MX Record', 'MX Count', 'MX Details',
                'SPF Record', 'SPF Content',
                'DKIM Record', 'DKIM Selectors',
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
                    'DKIM Record': 'Yes' if r.has_dkim else 'No',
                    'DKIM Selectors': r.dkim_selectors,
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
        description='Domain Security Scanner - Batch check DNS mail records and security configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f domains.txt
  %(prog)s -d example.com test.org
  %(prog)s -f domains.txt -o ./reports --max-retries 3
  %(prog)s -f domains.txt --dkim-selectors default,google,amazonses
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
    print(f"{Fore.GREEN}Domain Security Scanner v2.0")
    print(f"{Fore.GREEN}======================================")
    print(f"{Fore.CYAN}Scanning {len(domains)} domains")
    print(f"{Fore.CYAN}DKIM Selectors: {args.dkim_selectors}")
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
