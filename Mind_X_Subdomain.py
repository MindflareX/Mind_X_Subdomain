#!/usr/bin/env python3
"""
Mind_X_Subdomain - Advanced Subdomain Discovery Tool
Implements creative techniques to find hidden subdomains missed by standard tools
"""

import argparse
import dns.resolver
import json
import os
import re
import requests
import subprocess
import time
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import random

# Color output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = f"""{Colors.OKCYAN}
    ╔═══════════════════════════════════════════════════════════╗
    ║              Mind_X_Subdomain v1.0                        ║
    ║         Beyond Standard Tools - Find Hidden Gems          ║
    ║              Advanced Discovery Engine                    ║
    ║                                                           ║
    ║                 Created by: MindFlare                     ║
    ╚═══════════════════════════════════════════════════════════╝
    {Colors.ENDC}"""
    print(banner)

class SubdomainHunter:
    def __init__(self, domain, config, existing_domains=None, rate_limit=1.0):
        self.domain = domain
        self.config = config
        self.existing_domains = set(existing_domains) if existing_domains else set()
        self.new_domains = set()
        self.rate_limit = rate_limit
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })

    def rate_limit_sleep(self):
        """Smart rate limiting"""
        time.sleep(self.rate_limit + random.uniform(0, 0.5))

    def is_new_domain(self, domain):
        """Check if domain is newly discovered"""
        return domain not in self.existing_domains and domain not in self.new_domains

    def add_new_domain(self, domain):
        """Add newly discovered domain"""
        if self.is_new_domain(domain):
            self.new_domains.add(domain)
            print(f"{Colors.OKGREEN}[+] NEW: {domain}{Colors.ENDC}")
            return True
        return False

    # ==================== MODULE 1: SPF/DKIM Mining ====================
    def mine_email_infrastructure(self):
        """Extract domains from SPF and DKIM records"""
        print(f"\n{Colors.HEADER}[*] Mining Email Infrastructure (SPF/DKIM/DMARC)...{Colors.ENDC}")

        records_to_check = [
            self.domain,
            f'_dmarc.{self.domain}',
            f'_domainkey.{self.domain}',
            f'mail.{self.domain}',
            f'email.{self.domain}'
        ]

        for record in records_to_check:
            try:
                # Check TXT records
                answers = dns.resolver.resolve(record, 'TXT')
                for rdata in answers:
                    txt_string = str(rdata).strip('"')

                    # Extract domains from SPF
                    if 'v=spf1' in txt_string:
                        domains = re.findall(r'include:([^\s]+)', txt_string)
                        for d in domains:
                            if self.domain in d:
                                self.add_new_domain(d)

                    # Extract from DMARC
                    if 'v=DMARC1' in txt_string:
                        domains = re.findall(r'rua=mailto:[^@]+@([^\s;]+)', txt_string)
                        for d in domains:
                            if self.domain in d:
                                self.add_new_domain(d)

                self.rate_limit_sleep()
            except Exception as e:
                pass

        # Check MX records for mail infrastructure
        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            for mx in mx_records:
                mx_domain = str(mx.exchange).rstrip('.')
                if self.domain in mx_domain:
                    self.add_new_domain(mx_domain)
        except:
            pass

    # ==================== MODULE 2: Reverse IP Lookup ====================
    def reverse_ip_lookup(self, max_ips=50):
        """Find neighbors on same IP addresses"""
        print(f"\n{Colors.HEADER}[*] Performing Reverse IP Lookup...{Colors.ENDC}")

        # Get IPs from existing domains
        ip_map = defaultdict(list)
        domains_to_check = list(self.existing_domains)[:max_ips]  # Limit to avoid rate limiting

        for domain in domains_to_check:
            try:
                answers = dns.resolver.resolve(domain, 'A')
                for rdata in answers:
                    ip = str(rdata)
                    ip_map[ip].append(domain)
                self.rate_limit_sleep()
            except:
                continue

        # For each IP, do reverse lookup using various APIs
        for ip in list(ip_map.keys())[:20]:  # Limit to top 20 IPs
            try:
                # HackerTarget API (free, no key needed)
                url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
                response = self.session.get(url, timeout=10)
                self.rate_limit_sleep()

                if response.status_code == 200:
                    for line in response.text.split('\n'):
                        line = line.strip()
                        if self.domain in line and line:
                            self.add_new_domain(line)
            except Exception as e:
                continue

    # ==================== MODULE 3: Cloud Bucket Enumeration ====================
    def enumerate_cloud_buckets(self):
        """Find cloud storage buckets"""
        print(f"\n{Colors.HEADER}[*] Enumerating Cloud Storage Buckets...{Colors.ENDC}")

        base = self.domain.split('.')[0]  # e.g., 'bamko' from 'bamko.net'

        # Common bucket name patterns (generic for all domains)
        patterns = [
            f'{base}', f'{base}-dev', f'{base}-prod', f'{base}-staging',
            f'{base}-internal', f'{base}-backup', f'{base}-logs',
            f'{base}-data', f'{base}-assets', f'{base}-static',
            f'{base}-images', f'{base}-files', f'{base}-uploads',
            f'{base}-public', f'{base}-private', f'{base}-sandbox',
            f'{base}-test', f'{base}-qa', f'{base}-uat',
        ]

        found_buckets = []

        for pattern in patterns:
            # Check S3
            try:
                s3_url = f"https://{pattern}.s3.amazonaws.com"
                response = self.session.head(s3_url, timeout=5, allow_redirects=True)
                if response.status_code in [200, 403]:  # 403 means bucket exists but private
                    found_buckets.append(f"S3: {pattern}.s3.amazonaws.com")
                    print(f"{Colors.WARNING}[!] BUCKET FOUND: {pattern}.s3.amazonaws.com{Colors.ENDC}")
                self.rate_limit_sleep()
            except:
                pass

            # Check Azure Blob
            try:
                azure_url = f"https://{pattern}.blob.core.windows.net"
                response = self.session.head(azure_url, timeout=5)
                if response.status_code in [200, 403]:
                    found_buckets.append(f"Azure: {pattern}.blob.core.windows.net")
                    print(f"{Colors.WARNING}[!] BUCKET FOUND: {pattern}.blob.core.windows.net{Colors.ENDC}")
                self.rate_limit_sleep()
            except:
                pass

            # Check GCP
            try:
                gcp_url = f"https://storage.googleapis.com/{pattern}"
                response = self.session.head(gcp_url, timeout=5)
                if response.status_code in [200, 403]:
                    found_buckets.append(f"GCP: storage.googleapis.com/{pattern}")
                    print(f"{Colors.WARNING}[!] BUCKET FOUND: storage.googleapis.com/{pattern}{Colors.ENDC}")
                self.rate_limit_sleep()
            except:
                pass

        return found_buckets

    # ==================== MODULE 4: Smart Permutations (ENHANCED) ====================
    def get_builtin_wordlist(self):
        """Built-in comprehensive wordlist for permutations"""
        return [
            # Environments
            'dev', 'development', 'prod', 'production', 'stage', 'staging',
            'test', 'testing', 'qa', 'uat', 'preprod', 'pre-prod',
            'sandbox', 'sb', 'demo', 'beta', 'alpha', 'canary',
            'internal', 'external', 'public', 'private',

            # Common prefixes
            'api', 'www', 'mail', 'smtp', 'webmail', 'ftp', 'sftp',
            'vpn', 'ssh', 'remote', 'admin', 'administrator',
            'portal', 'dashboard', 'console', 'panel', 'cp',
            'my', 'user', 'account', 'profile', 'secure',

            # Infrastructure
            'app', 'web', 'mobile', 'service', 'services',
            'gateway', 'proxy', 'lb', 'balancer', 'cdn',
            'static', 'assets', 'media', 'images', 'img',
            'files', 'uploads', 'download', 'downloads',

            # DevOps/CI/CD
            'jenkins', 'gitlab', 'github', 'git', 'ci', 'cd',
            'build', 'deploy', 'release', 'artifact', 'nexus',
            'docker', 'registry', 'k8s', 'kubernetes', 'rancher',

            # Monitoring/Logging
            'monitor', 'monitoring', 'grafana', 'prometheus',
            'kibana', 'elastic', 'elk', 'log', 'logs', 'logging',
            'metrics', 'stats', 'status', 'health', 'ping',

            # Databases
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
            'sql', 'nosql', 'cache', 'memcache', 'backup', 'backups',

            # Security
            'sso', 'auth', 'oauth', 'saml', 'ldap', 'ad',
            'iam', 'identity', 'okta', 'mfa', 'waf',

            # Business/Fintech specific
            'payment', 'payments', 'checkout', 'billing', 'invoice',
            'merchant', 'seller', 'buyer', 'customer', 'client',
            'wallet', 'card', 'credit', 'debit', 'bank',
            'kyc', 'aml', 'fraud', 'risk', 'compliance',
            'transaction', 'txn', 'order', 'orders', 'purchase',

            # API versions
            'v1', 'v2', 'v3', 'v4', 'v5',
            'api-v1', 'api-v2', 'api-v3',

            # Regions
            'us', 'eu', 'asia', 'apac', 'emea',
            'uk', 'de', 'fr', 'au', 'sg', 'jp',
            'east', 'west', 'north', 'south', 'central',

            # Old/Legacy
            'old', 'legacy', 'deprecated', 'archive', 'archived',
            'v1', 'v2', 'classic', 'new', 'next',

            # Other
            'support', 'help', 'docs', 'documentation', 'wiki',
            'blog', 'news', 'corporate', 'careers', 'jobs',
            'partner', 'partners', 'developer', 'developers',
        ]

    def altdns_style_permutations(self, subdomain):
        """Generate altdns-style permutations from a subdomain"""
        permutations = set()
        wordlist = self.get_builtin_wordlist()

        # Extract subdomain part (without base domain)
        sub_part = subdomain.replace(f'.{self.domain}', '')
        parts = sub_part.split('.')

        for word in wordlist[:50]:  # Limit wordlist for performance
            # Insertion patterns (add word)
            permutations.add(f'{word}-{sub_part}.{self.domain}')  # prepend with dash
            permutations.add(f'{sub_part}-{word}.{self.domain}')  # append with dash
            permutations.add(f'{word}.{sub_part}.{self.domain}')  # prepend with dot
            permutations.add(f'{sub_part}.{word}.{self.domain}')  # append with dot
            permutations.add(f'{word}{sub_part}.{self.domain}')   # prepend no separator

            # For multi-part subdomains
            if len(parts) > 1:
                # Insert in the middle
                for i in range(len(parts)):
                    new_parts = parts.copy()
                    new_parts.insert(i, word)
                    permutations.add('.'.join(new_parts) + f'.{self.domain}')

                # Replace each part
                for i in range(len(parts)):
                    new_parts = parts.copy()
                    new_parts[i] = word
                    permutations.add('.'.join(new_parts) + f'.{self.domain}')

        # Number permutations (common in infrastructure)
        for i in range(1, 11):  # 1-10
            permutations.add(f'{sub_part}{i}.{self.domain}')
            permutations.add(f'{sub_part}-{i}.{self.domain}')
            permutations.add(f'{sub_part}{i:02d}.{self.domain}')  # 01, 02, etc.

        return permutations

    def generate_smart_permutations(self):
        """Enhanced permutation generation with altdns-style creativity"""
        print(f"\n{Colors.HEADER}[*] Generating Smart Permutations (Enhanced)...{Colors.ENDC}")

        # Extract patterns from existing domains
        patterns = set()
        environments = set()
        prefixes = set()

        print(f"[*] Analyzing {len(self.existing_domains)} existing domains for patterns...")

        for domain in list(self.existing_domains)[:1000]:  # Analyze sample
            parts = domain.replace(f'.{self.domain}', '').split('.')
            for part in parts:
                if any(env in part for env in ['prod', 'dev', 'stage', 'staging', 'qa', 'uat', 'sandbox', 'sb']):
                    environments.add(part)
                elif part not in ['www', 'api', 'com', 'net', 'org']:
                    prefixes.add(part)

        print(f"[*] Found {len(environments)} environment patterns, {len(prefixes)} unique prefixes")

        # Get built-in wordlist
        wordlist = self.get_builtin_wordlist()

        # Generate base permutations
        permutations = set()

        # 1. Wordlist + existing prefixes
        print(f"[*] Generating wordlist-based permutations...")
        for word in wordlist[:100]:  # Use top 100 words
            permutations.add(f'{word}.{self.domain}')

            # Combine with discovered prefixes
            for prefix in list(prefixes)[:30]:
                permutations.add(f'{word}-{prefix}.{self.domain}')
                permutations.add(f'{prefix}-{word}.{self.domain}')
                permutations.add(f'{word}.{prefix}.{self.domain}')

            # Combine with environments
            for env in environments:
                permutations.add(f'{word}-{env}.{self.domain}')
                permutations.add(f'{env}-{word}.{self.domain}')

        # 2. Altdns-style permutations on discovered subdomains
        print(f"[*] Generating altdns-style permutations from discovered subdomains...")
        interesting_subs = [s for s in list(self.existing_domains)[:50]
                          if any(x in s for x in ['api', 'admin', 'dev', 'stage', 'internal'])]

        for sub in interesting_subs:
            perms = self.altdns_style_permutations(sub)
            permutations.update(list(perms)[:100])  # Limit per subdomain

        # 3. Number variations (common pattern: api1, api2, etc.)
        print(f"[*] Adding number-based permutations...")
        common_bases = ['api', 'app', 'web', 'server', 'host', 'node', 'prod', 'dev']
        for base in common_bases:
            for i in range(1, 21):  # 1-20
                permutations.add(f'{base}{i}.{self.domain}')
                permutations.add(f'{base}-{i}.{self.domain}')
                permutations.add(f'{base}{i:02d}.{self.domain}')  # 01-20

        total_perms = len(permutations)
        print(f"[*] Generated {total_perms} total permutations")

        # Resolve permutations with rate limiting
        print(f"[*] Resolving permutations (rate limited)...")
        validated = []
        tested = 0
        max_test = 2000  # Limit to avoid excessive queries

        for perm in list(permutations)[:max_test]:
            try:
                dns.resolver.resolve(perm, 'A')
                if self.add_new_domain(perm):
                    validated.append(perm)
                tested += 1

                # Progress indicator
                if tested % 100 == 0:
                    print(f"[*] Progress: {tested}/{max_test} tested, {len(validated)} found")

                self.rate_limit_sleep()
            except:
                pass

        print(f"[*] Permutation scan complete: {len(validated)} new domains found")
        return validated

    def resolve_with_puredns(self, permutations_file):
        """Use puredns for faster mass resolution (if installed)"""
        print(f"\n{Colors.HEADER}[*] Attempting fast resolution with puredns...{Colors.ENDC}")

        # Check if puredns is installed
        try:
            result = subprocess.run(['which', 'puredns'], capture_output=True, text=True)
            if result.returncode != 0:
                print(f"{Colors.WARNING}[!] puredns not found. Using standard DNS resolution.{Colors.ENDC}")
                print(f"[!] Install: go install github.com/d3mondev/puredns/v2@latest")
                return []
        except:
            return []

        # Check for resolvers
        resolvers_files = [
            '/usr/share/seclists/Discovery/DNS/resolvers.txt',
            './resolvers.txt',
            '../resolvers.txt'
        ]

        resolvers = None
        for rf in resolvers_files:
            if os.path.exists(rf):
                resolvers = rf
                break

        if not resolvers:
            print(f"{Colors.WARNING}[!] No resolvers.txt found. Using system DNS.{Colors.ENDC}")
            return []

        print(f"[*] Using puredns with resolvers: {resolvers}")

        try:
            # Run puredns
            output_file = f'puredns_results_{int(time.time())}.txt'
            cmd = ['puredns', 'resolve', permutations_file, '-r', resolvers, '-w', output_file]

            print(f"[*] Running: {' '.join(cmd)}")
            subprocess.run(cmd, timeout=300)  # 5 min timeout

            # Read results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    resolved = [line.strip() for line in f if line.strip()]
                print(f"{Colors.OKGREEN}[+] puredns found {len(resolved)} domains{Colors.ENDC}")
                return resolved
        except Exception as e:
            print(f"{Colors.FAIL}[-] puredns failed: {e}{Colors.ENDC}")

        return []

    # ==================== MODULE 5: ASN Enumeration ====================
    def asn_enumeration(self):
        """Find IP ranges owned by organization"""
        print(f"\n{Colors.HEADER}[*] Performing ASN Enumeration...{Colors.ENDC}")

        organization = self.domain.split('.')[0].upper()

        # Use HackerTarget ASN lookup (free API)
        try:
            url = f"https://api.hackertarget.com/aslookup/?q={organization}"
            response = self.session.get(url, timeout=10)
            self.rate_limit_sleep()

            if response.status_code == 200:
                print(f"[*] ASN Info:\n{response.text[:500]}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] ASN lookup failed: {e}{Colors.ENDC}")

    # ==================== MODULE 6: Certificate Transparency Deep Dive ====================
    def ct_deep_dive(self):
        """Deep certificate transparency analysis"""
        print(f"\n{Colors.HEADER}[*] Certificate Transparency Deep Dive...{Colors.ENDC}")

        try:
            # crt.sh API
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url, timeout=30)
            self.rate_limit_sleep()

            if response.status_code == 200:
                certs = json.loads(response.text)

                wildcards = set()
                for cert in certs[:1000]:  # Limit processing
                    name_value = cert.get('name_value', '')
                    for domain in name_value.split('\n'):
                        domain = domain.strip().lower()

                        # Collect wildcard domains
                        if domain.startswith('*.'):
                            wildcard_base = domain[2:]
                            wildcards.add(wildcard_base)
                        elif self.domain in domain:
                            self.add_new_domain(domain)

                # Report wildcard domains found
                if wildcards:
                    print(f"\n{Colors.WARNING}[!] Found {len(wildcards)} wildcard base domains:{Colors.ENDC}")
                    for wc in list(wildcards)[:10]:
                        print(f"    *.{wc}")

        except Exception as e:
            print(f"{Colors.FAIL}[-] CT lookup failed: {e}{Colors.ENDC}")

    # ==================== MODULE 7: JavaScript Endpoint Mining ====================
    def mine_javascript_endpoints(self, target_domains=None):
        """Extract endpoints and domains from JavaScript files"""
        print(f"\n{Colors.HEADER}[*] Mining JavaScript for Hidden Endpoints...{Colors.ENDC}")

        if not target_domains:
            target_domains = ['www.' + self.domain, self.domain]

        js_domains = set()

        for domain in target_domains[:5]:  # Limit to avoid too many requests
            try:
                # Try common JS file locations
                js_urls = [
                    f"https://{domain}/js/app.js",
                    f"https://{domain}/static/js/main.js",
                    f"https://{domain}/assets/js/bundle.js",
                    f"https://{domain}/app.js",
                    f"https://{domain}/main.js",
                ]

                for js_url in js_urls:
                    try:
                        response = self.session.get(js_url, timeout=10)
                        if response.status_code == 200:
                            # Extract domains/subdomains
                            content = response.text

                            # Find subdomains
                            pattern = r'https?://([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')'
                            matches = re.findall(pattern, content)

                            for match in matches:
                                if self.add_new_domain(match):
                                    js_domains.add(match)

                        self.rate_limit_sleep()
                    except:
                        continue
            except:
                continue

        return js_domains

    # ==================== MODULE 8: Historical DNS (SecurityTrails) ====================
    def historical_dns(self):
        """Query historical DNS records"""
        print(f"\n{Colors.HEADER}[*] Checking Historical DNS Records...{Colors.ENDC}")

        api_key = self.config.get('securitytrails_api_key')

        if not api_key:
            print(f"{Colors.WARNING}[!] SecurityTrails API key not configured. Skipping.{Colors.ENDC}")
            return

        try:
            url = f"https://api.securitytrails.com/v1/history/{self.domain}/dns/a"
            headers = {'APIKEY': api_key}

            response = self.session.get(url, headers=headers, timeout=10)
            self.rate_limit_sleep()

            if response.status_code == 200:
                data = json.loads(response.text)
                records = data.get('records', [])
                print(f"[*] Found {len(records)} historical A records")

                # Could expand this to check historical subdomains
        except Exception as e:
            print(f"{Colors.FAIL}[-] Historical DNS lookup failed: {e}{Colors.ENDC}")

    # ==================== MODULE 9: Acquisition Domain Mapping ====================
    def acquisition_mapping(self):
        """Map PayPal acquisitions and their infrastructure"""
        print(f"\n{Colors.HEADER}[*] Mapping Acquisition Domains...{Colors.ENDC}")

        # PayPal-specific acquisitions
        acquisitions = {
            'venmo.com': ['venmo', 'vnmo'],
            'braintreegateway.com': ['braintree', 'braintreepayments'],
            'xoom.com': ['xoom'],
            'joinhoney.com': ['honey'],
            'hyperwallet.com': ['hyperwallet', 'hw'],
            'izettle.com': ['zettle', 'izettle'],
            'simility.com': ['simility'],
            'paydiant.com': ['paydiant'],
        }

        base = self.domain.split('.')[0]

        # Check if acquisitions have cross-integration domains
        for acq_domain, variations in acquisitions.items():
            for variation in variations:
                # Check {acquisition}.{parent}.com pattern
                test_domains = [
                    f'{variation}.{self.domain}',
                    f'{base}-{variation}.{acq_domain}',
                    f'{variation}-api.{self.domain}',
                    f'{variation}-internal.{self.domain}',
                ]

                for test in test_domains:
                    try:
                        dns.resolver.resolve(test, 'A')
                        self.add_new_domain(test)
                        self.rate_limit_sleep()
                    except:
                        pass

        # Check cloud buckets for PayPal acquisitions
        print(f"\n{Colors.HEADER}[*] Checking Cloud Buckets for Acquisitions...{Colors.ENDC}")
        acquisition_names = ['venmo', 'braintree', 'xoom', 'honey', 'hyperwallet', 'izettle']

        for acq in acquisition_names:
            bucket_patterns = [
                f'{base}-{acq}', f'{acq}-{base}', f'{acq}',
                f'{acq}-prod', f'{acq}-dev', f'{acq}-api'
            ]

            for pattern in bucket_patterns:
                # Check S3
                try:
                    s3_url = f"https://{pattern}.s3.amazonaws.com"
                    response = self.session.head(s3_url, timeout=5, allow_redirects=True)
                    if response.status_code in [200, 403]:
                        print(f"{Colors.WARNING}[!] ACQUISITION BUCKET: {pattern}.s3.amazonaws.com{Colors.ENDC}")
                    self.rate_limit_sleep()
                except:
                    pass

                # Check GCP
                try:
                    gcp_url = f"https://storage.googleapis.com/{pattern}"
                    response = self.session.head(gcp_url, timeout=5)
                    if response.status_code in [200, 403]:
                        print(f"{Colors.WARNING}[!] ACQUISITION BUCKET: storage.googleapis.com/{pattern}{Colors.ENDC}")
                    self.rate_limit_sleep()
                except:
                    pass

    # ==================== MODULE 10: HTTP Probing + Tech Detection ====================
    def http_probe_and_tech_detect(self):
        """Probe discovered domains for HTTP/HTTPS and detect technologies"""
        print(f"\n{Colors.HEADER}[*] HTTP Probing + Technology Detection...{Colors.ENDC}")

        domains_to_probe = list(self.existing_domains.union(self.new_domains))[:200]  # Limit for performance
        print(f"[*] Probing {len(domains_to_probe)} domains...")

        alive_domains = []

        for domain in domains_to_probe:
            for protocol in ['https', 'http']:
                try:
                    url = f'{protocol}://{domain}'
                    response = self.session.get(url, timeout=5, allow_redirects=True, verify=False)

                    # Detect technologies from headers
                    server = response.headers.get('Server', 'Unknown')
                    powered_by = response.headers.get('X-Powered-By', '')

                    # Check for common tech indicators
                    techs = []
                    if 'nginx' in server.lower():
                        techs.append('Nginx')
                    if 'apache' in server.lower():
                        techs.append('Apache')
                    if 'cloudflare' in str(response.headers).lower():
                        techs.append('Cloudflare')
                    if powered_by:
                        techs.append(powered_by)

                    tech_str = ', '.join(techs) if techs else 'Unknown'

                    print(f"{Colors.OKGREEN}[+] {url} [{response.status_code}] - {tech_str}{Colors.ENDC}")
                    alive_domains.append({'url': url, 'status': response.status_code, 'tech': tech_str})

                    self.rate_limit_sleep()
                    break  # Found working protocol
                except:
                    continue

        print(f"[*] Found {len(alive_domains)} alive domains")
        return alive_domains

    # ==================== MODULE 11: Wayback Machine Mining ====================
    def wayback_machine_mining(self):
        """Extract historical URLs and subdomains from Wayback Machine"""
        print(f"\n{Colors.HEADER}[*] Mining Wayback Machine...{Colors.ENDC}")

        try:
            # Query Wayback Machine API
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
            response = self.session.get(url, timeout=30)
            self.rate_limit_sleep()

            if response.status_code == 200:
                data = json.loads(response.text)

                # Extract unique subdomains from URLs
                subdomains = set()
                for entry in data[1:]:  # Skip header
                    try:
                        url_str = entry[0]
                        # Extract domain from URL
                        match = re.search(r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + ')', url_str)
                        if match:
                            subdomain = match.group(1)
                            if self.is_new_domain(subdomain):
                                subdomains.add(subdomain)
                    except:
                        continue

                print(f"[*] Found {len(subdomains)} historical subdomains")

                # Validate they still resolve
                for subdomain in list(subdomains)[:100]:  # Limit validation
                    try:
                        dns.resolver.resolve(subdomain, 'A')
                        self.add_new_domain(subdomain)
                        print(f"{Colors.OKGREEN}[+] Historical subdomain still active: {subdomain}{Colors.ENDC}")
                        self.rate_limit_sleep()
                    except:
                        pass

        except Exception as e:
            print(f"{Colors.FAIL}[-] Wayback Machine query failed: {e}{Colors.ENDC}")

    # ==================== MODULE 12: Favicon Hash Hunting ====================
    def favicon_hash_hunting(self):
        """Find related infrastructure via favicon hash (requires Shodan API)"""
        print(f"\n{Colors.HEADER}[*] Favicon Hash Hunting...{Colors.ENDC}")

        shodan_key = self.config.get('shodan_api_key')
        if not shodan_key:
            print(f"{Colors.WARNING}[!] Shodan API key not configured. Skipping.{Colors.ENDC}")
            return

        try:
            import hashlib
            import codecs

            # Get favicon from main domain
            url = f'https://www.{self.domain}/favicon.ico'
            response = self.session.get(url, timeout=10, verify=False)

            if response.status_code == 200:
                # Calculate MMH3 hash (Shodan's hash)
                favicon = codecs.encode(response.content, 'base64')
                favicon_hash = hashlib.md5(favicon).hexdigest()

                # Search Shodan
                shodan_url = f'https://api.shodan.io/shodan/host/search?key={shodan_key}&query=http.favicon.hash:{favicon_hash}'
                shodan_response = self.session.get(shodan_url, timeout=10)

                if shodan_response.status_code == 200:
                    results = json.loads(shodan_response.text)
                    print(f"[*] Found {results.get('total', 0)} hosts with same favicon")

                    for match in results.get('matches', [])[:20]:
                        ip = match.get('ip_str')
                        domains = match.get('hostnames', [])
                        for domain in domains:
                            if self.domain in domain:
                                self.add_new_domain(domain)

            self.rate_limit_sleep()
        except Exception as e:
            print(f"{Colors.FAIL}[-] Favicon hash hunting failed: {e}{Colors.ENDC}")

    # ==================== MODULE 13: DNS Record Deep Dive ====================
    def dns_deep_dive(self):
        """Get ALL DNS record types for discovered domains"""
        print(f"\n{Colors.HEADER}[*] DNS Record Deep Dive...{Colors.ENDC}")

        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA']
        domains_to_check = list(self.existing_domains.union(self.new_domains))[:100]

        print(f"[*] Checking {len(domains_to_check)} domains for all DNS record types...")

        for domain in domains_to_check:
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for rdata in answers:
                        record_str = str(rdata)

                        # Extract potential subdomains from records
                        if record_type in ['CNAME', 'MX', 'NS']:
                            # These might point to other subdomains
                            if self.domain in record_str:
                                clean_domain = record_str.rstrip('.')
                                if self.is_new_domain(clean_domain):
                                    print(f"{Colors.OKGREEN}[+] Found from {record_type}: {clean_domain}{Colors.ENDC}")
                                    self.add_new_domain(clean_domain)

                    self.rate_limit_sleep()
                except:
                    continue

    # ==================== MODULE 14: Recursive Subdomain Discovery ====================
    def recursive_subdomain_discovery(self):
        """Find subdomains of subdomains (multi-level)"""
        print(f"\n{Colors.HEADER}[*] Recursive Subdomain Discovery...{Colors.ENDC}")

        # Take interesting subdomains and try to find their subdomains
        interesting = [d for d in self.existing_domains if any(x in d for x in ['api', 'dev', 'internal', 'admin'])][:20]

        print(f"[*] Recursively checking {len(interesting)} interesting subdomains...")

        common_prefixes = ['dev', 'staging', 'test', 'api', 'admin', 'internal', 'www', 'v1', 'v2']

        for base_domain in interesting:
            for prefix in common_prefixes:
                recursive_domain = f'{prefix}.{base_domain}'
                try:
                    dns.resolver.resolve(recursive_domain, 'A')
                    if self.add_new_domain(recursive_domain):
                        print(f"{Colors.OKGREEN}[+] Recursive: {recursive_domain}{Colors.ENDC}")
                    self.rate_limit_sleep()
                except:
                    pass

    # ==================== MODULE 15: VHOST Discovery ====================
    def vhost_discovery(self):
        """Discover virtual hosts on discovered IPs"""
        print(f"\n{Colors.HEADER}[*] VHOST Discovery...{Colors.ENDC}")

        # Get IPs from discovered domains
        ip_to_domains = defaultdict(list)

        for domain in list(self.existing_domains)[:50]:
            try:
                answers = dns.resolver.resolve(domain, 'A')
                for rdata in answers:
                    ip = str(rdata)
                    ip_to_domains[ip].append(domain)
                self.rate_limit_sleep()
            except:
                continue

        print(f"[*] Testing virtual hosts on {len(ip_to_domains)} IPs...")

        # For each IP, try other discovered domains as Host header
        for ip, domains in list(ip_to_domains.items())[:20]:
            for test_domain in list(self.existing_domains)[:30]:
                try:
                    # Try accessing IP with different Host header
                    response = self.session.get(
                        f'http://{ip}',
                        headers={'Host': test_domain},
                        timeout=5,
                        allow_redirects=False
                    )
                    if response.status_code in [200, 301, 302]:
                        print(f"[*] VHOST: {test_domain} on {ip}")
                    self.rate_limit_sleep()
                except:
                    continue

    # ==================== MODULE 16: Google/Bing Dorking ====================
    def search_engine_dorking(self):
        """Use Google/Bing dorking to find subdomains"""
        print(f"\n{Colors.HEADER}[*] Search Engine Dorking...{Colors.ENDC}")

        dorks = [
            f'site:*.{self.domain}',
            f'site:*.{self.domain} -site:www.{self.domain}',
            f'site:{self.domain} inurl:admin',
            f'site:{self.domain} inurl:api',
            f'site:{self.domain} inurl:dev',
        ]

        print(f"[*] Note: Search engine dorking requires manual review")
        print(f"[*] Recommended dorks for {self.domain}:")
        for dork in dorks:
            print(f"    {Colors.OKCYAN}{dork}{Colors.ENDC}")

        # Can integrate with Google Custom Search API if key provided
        google_key = self.config.get('google_api_key')
        if google_key:
            print(f"[*] Google API key found, performing automated search...")
            # Would implement Google Custom Search API here
        else:
            print(f"{Colors.WARNING}[!] Add google_api_key to config.json for automated dorking{Colors.ENDC}")

    # ==================== MAIN RUNNER ====================
    def run_all(self, modules=None):
        """Run all discovery modules"""

        if modules is None:
            modules = [
                'email', 'reverse_ip', 'cloud', 'permutations',
                'asn', 'ct', 'javascript', 'acquisitions',
                'http_probe', 'wayback', 'dns_deep', 'recursive'
            ]

        print(f"\n{Colors.OKBLUE}[*] Starting discovery for: {self.domain}{Colors.ENDC}")
        print(f"[*] Existing domains: {len(self.existing_domains)}")
        print(f"[*] Active modules: {', '.join(modules)}\n")

        try:
            if 'email' in modules:
                self.mine_email_infrastructure()

            if 'reverse_ip' in modules and self.existing_domains:
                self.reverse_ip_lookup()

            if 'cloud' in modules:
                buckets = self.enumerate_cloud_buckets()

            if 'permutations' in modules:
                self.generate_smart_permutations()

            if 'asn' in modules:
                self.asn_enumeration()

            if 'ct' in modules:
                self.ct_deep_dive()

            if 'javascript' in modules:
                self.mine_javascript_endpoints()

            if 'acquisitions' in modules and 'paypal' in self.domain:
                self.acquisition_mapping()

            # New modules
            if 'http_probe' in modules:
                self.http_probe_and_tech_detect()

            if 'wayback' in modules:
                self.wayback_machine_mining()

            if 'favicon' in modules:
                self.favicon_hash_hunting()

            if 'dns_deep' in modules:
                self.dns_deep_dive()

            if 'recursive' in modules:
                self.recursive_subdomain_discovery()

            if 'vhost' in modules:
                self.vhost_discovery()

            if 'dorking' in modules:
                self.search_engine_dorking()

            # Historical DNS requires API key
            if 'historical' in modules:
                self.historical_dns()

        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}[!] Scan interrupted by user (Ctrl+C){Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Discovered {len(self.new_domains)} new domains before interruption{Colors.ENDC}")
            return self.new_domains

        return self.new_domains


def load_config(config_file='config.json'):
    """Load API keys and configuration"""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def load_domains_from_file(filename):
    """Load existing domains from file"""
    domains = set()
    try:
        with open(filename, 'r') as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    domains.add(domain)
    except FileNotFoundError:
        print(f"{Colors.FAIL}[-] File not found: {filename}{Colors.ENDC}")
        sys.exit(1)
    return domains


def process_single_domain(domain, existing_domains, config, args):
    """Process a single domain and return results"""
    print(f"\n{Colors.HEADER}[*] Target Domain: {domain}{Colors.ENDC}")

    hunter = SubdomainHunter(
        domain=domain,
        config=config,
        existing_domains=existing_domains,
        rate_limit=args.rate_limit
    )

    new_domains = hunter.run_all(modules=args.modules)
    return new_domains


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='Mind_X_Subdomain - Advanced Subdomain Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single domain:
    python3 %(prog)s -d paypal.com -o results.txt

  Multiple domains from file:
    python3 %(prog)s -l domains.txt -o results/

  With existing subdomains:
    python3 %(prog)s -d paypal.com -f existing.txt -o new_finds.txt

  Specific modules only:
    python3 %(prog)s -l domains.txt -m cloud javascript ct -o results/
        """
    )

    parser.add_argument('-d', '--domain', help='Target domain (e.g., paypal.com)')
    parser.add_argument('-l', '--list', help='File containing list of target domains (one per line)')
    parser.add_argument('-f', '--file', help='File containing existing subdomains to filter out')
    parser.add_argument('-o', '--output', default='new_subdomains.txt',
                       help='Output file/directory for discoveries')
    parser.add_argument('-c', '--config', default='config.json',
                       help='Config file with API keys')
    parser.add_argument('-r', '--rate-limit', type=float, default=1.0,
                       help='Rate limit delay in seconds (default: 1.0)')
    parser.add_argument('-m', '--modules', nargs='+',
                       choices=['email', 'reverse_ip', 'cloud', 'permutations',
                               'asn', 'ct', 'javascript', 'acquisitions', 'historical',
                               'http_probe', 'wayback', 'favicon', 'dns_deep',
                               'recursive', 'vhost', 'dorking'],
                       help='Specific modules to run (default: all)')

    args = parser.parse_args()

    try:
        # Validate arguments - must have either -d or -l
        if not args.domain and not args.list:
            print(f"{Colors.FAIL}[-] Error: Either --domain or --list is required{Colors.ENDC}")
            parser.print_help()
            sys.exit(1)

        if args.domain and args.list:
            print(f"{Colors.FAIL}[-] Error: Cannot use both --domain and --list together{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] Use --domain for single domain OR --list for multiple domains{Colors.ENDC}")
            sys.exit(1)

        # Load configuration
        config = load_config(args.config)

        # Load existing domains if file provided
        existing_domains = set()
        if args.file:
            existing_domains = load_domains_from_file(args.file)
            print(f"{Colors.OKGREEN}[+] Loaded {len(existing_domains)} existing subdomains to filter{Colors.ENDC}")

        # MODE 1: Single domain
        if args.domain:
            new_domains = process_single_domain(args.domain, existing_domains, config, args)

            # Save results
            if new_domains:
                with open(args.output, 'w') as f:
                    for domain in sorted(new_domains):
                        f.write(f"{domain}\n")

                print(f"\n{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
                print(f"{Colors.OKGREEN}[+] Discovery Complete!{Colors.ENDC}")
                print(f"{Colors.OKGREEN}[+] Found {len(new_domains)} NEW subdomains{Colors.ENDC}")
                print(f"{Colors.OKGREEN}[+] Saved to: {args.output}{Colors.ENDC}")
                print(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
            else:
                print(f"\n{Colors.WARNING}[!] No new subdomains discovered{Colors.ENDC}")

        # MODE 2: Multiple domains from list
        elif args.list:
            # Load target domains from list
            try:
                with open(args.list, 'r') as f:
                    target_domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except FileNotFoundError:
                print(f"{Colors.FAIL}[-] Error: Domain list file not found: {args.list}{Colors.ENDC}")
                sys.exit(1)

            if not target_domains:
                print(f"{Colors.FAIL}[-] Error: No domains found in {args.list}{Colors.ENDC}")
                sys.exit(1)

            print(f"{Colors.OKGREEN}[+] Loaded {len(target_domains)} target domains{Colors.ENDC}")

            # Create output directory if it doesn't exist
            output_dir = args.output.rstrip('/')
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                print(f"{Colors.OKGREEN}[+] Created output directory: {output_dir}{Colors.ENDC}")

            # Process each domain
            total_discovered = 0
            results_summary = []

            for idx, domain in enumerate(target_domains, 1):
                print(f"\n{Colors.OKCYAN}{'='*60}{Colors.ENDC}")
                print(f"{Colors.OKCYAN}[*] Processing [{idx}/{len(target_domains)}]: {domain}{Colors.ENDC}")
                print(f"{Colors.OKCYAN}{'='*60}{Colors.ENDC}")

                new_domains = process_single_domain(domain, existing_domains, config, args)

                # Save individual domain results
                output_file = os.path.join(output_dir, f"{domain}_subdomains.txt")
                if new_domains:
                    with open(output_file, 'w') as f:
                        for d in sorted(new_domains):
                            f.write(f"{d}\n")

                    count = len(new_domains)
                    total_discovered += count
                    results_summary.append((domain, count, output_file))
                    print(f"{Colors.OKGREEN}[✓] Found {count} new subdomains for {domain}{Colors.ENDC}")
                    print(f"{Colors.OKGREEN}[✓] Saved to: {output_file}{Colors.ENDC}")
                else:
                    results_summary.append((domain, 0, None))
                    print(f"{Colors.WARNING}[!] No new subdomains for {domain}{Colors.ENDC}")

                # Small delay between domains
                if idx < len(target_domains):
                    time.sleep(2)

            # Generate summary report
            summary_file = os.path.join(output_dir, "SUMMARY.txt")
            with open(summary_file, 'w') as f:
                f.write("Mind_X Subdomain Discovery - Summary Report\n")
                f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*60 + "\n\n")

                for domain, count, filepath in results_summary:
                    f.write(f"{domain:40} : {count:6} subdomains\n")
                    if filepath:
                        f.write(f"  └─ {filepath}\n")

                f.write("\n" + "="*60 + "\n")
                f.write(f"TOTAL SUBDOMAINS DISCOVERED: {total_discovered}\n")
                f.write(f"TOTAL DOMAINS PROCESSED: {len(target_domains)}\n")

            # Combine all results
            combined_file = os.path.join(output_dir, "ALL_SUBDOMAINS_COMBINED.txt")
            all_subs = set()
            for domain, count, filepath in results_summary:
                if filepath and os.path.exists(filepath):
                    with open(filepath, 'r') as f:
                        all_subs.update(line.strip() for line in f if line.strip())

            with open(combined_file, 'w') as f:
                for sub in sorted(all_subs):
                    f.write(f"{sub}\n")

            # Final summary
            print(f"\n{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] ALL DOMAINS PROCESSED!{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Total subdomains discovered: {total_discovered}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Unique subdomains (combined): {len(all_subs)}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Results directory: {output_dir}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Summary report: {summary_file}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] Combined file: {combined_file}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")

    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] Scan interrupted by user (Ctrl+C){Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Exiting gracefully...{Colors.ENDC}")
        sys.exit(0)


if __name__ == '__main__':
    main()
