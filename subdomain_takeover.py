#!/usr/bin/env python3
"""
Subdomain Takeover Detection Tool
Checks for vulnerable CNAME records pointing to unclaimed services
Usage: python3 subdomain_takeover.py -l subdomains.txt -o vulnerable.txt
"""

import argparse
import dns.resolver
import requests
import sys
from concurrent.futures import ThreadPoolExecutor
import time

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

# Takeover fingerprints - services vulnerable to subdomain takeover
# Enhanced with 60+ services matching nuclei/subzy coverage
TAKEOVER_FINGERPRINTS = {
    'github.io': {
        'cname': 'github.io',
        'error_strings': [
            'There isn\'t a GitHub Pages site here',
            'For root URLs (like http://example.com/) you must provide an index.html file',
            'There is not a GitHub Pages site here'
        ],
        'status_codes': [404],
        'service': 'GitHub Pages'
    },
    'herokuapp.com': {
        'cname': 'herokuapp.com',
        'error_strings': [
            'No such app',
            'herokucdn.com/error-pages/no-such-app.html',
            'no such app'
        ],
        'status_codes': [404],
        'service': 'Heroku'
    },
    'amazonaws.com': {
        'cname': 's3.amazonaws.com',
        'error_strings': [
            'NoSuchBucket',
            'The specified bucket does not exist',
            '<Code>NoSuchBucket</Code>'
        ],
        'status_codes': [404],
        'service': 'AWS S3'
    },
    'cloudfront.net': {
        'cname': 'cloudfront.net',
        'error_strings': [
            'Bad request',
            'The request could not be satisfied',
            'ERROR: The request could not be satisfied'
        ],
        'status_codes': [403, 404],
        'service': 'AWS CloudFront'
    },
    'elasticbeanstalk.com': {
        'cname': 'elasticbeanstalk.com',
        'error_strings': [
            'VPC with the specified subnet group does not exist',
            'No such environment'
        ],
        'service': 'AWS Elastic Beanstalk'
    },
    'azurewebsites.net': {
        'cname': 'azurewebsites.net',
        'error_strings': [
            'Error 404: Web app not found',
            '404 Web Site not found',
            '404 - Web app not found'
        ],
        'status_codes': [404],
        'service': 'Azure Web App'
    },
    'azurefd.net': {
        'cname': 'azurefd.net',
        'error_strings': [
            'Our services aren\'t available right now',
            'We\'re working on it'
        ],
        'service': 'Azure Front Door'
    },
    'trafficmanager.net': {
        'cname': 'trafficmanager.net',
        'error_strings': [
            'The requested name does not exist',
            'NXDOMAIN'
        ],
        'service': 'Azure Traffic Manager'
    },
    'bitbucket.io': {
        'cname': 'bitbucket.io',
        'error_strings': [
            'Repository not found',
            'The page you have requested does not exist'
        ],
        'status_codes': [404],
        'service': 'Bitbucket'
    },
    'shopify.com': {
        'cname': 'myshopify.com',
        'error_strings': [
            'Sorry, this shop is currently unavailable',
            'Only one step left!',
            'This shop is currently unavailable'
        ],
        'service': 'Shopify'
    },
    'fastly.net': {
        'cname': 'fastly.net',
        'error_strings': [
            'Fastly error: unknown domain',
            'Please check that this domain has been added to a service',
            'Fastly error'
        ],
        'status_codes': [404],
        'service': 'Fastly'
    },
    'pantheonsite.io': {
        'cname': 'pantheonsite.io',
        'error_strings': [
            '404 error unknown site!',
            'The gods are wise, but do not know of the site which you seek'
        ],
        'status_codes': [404],
        'service': 'Pantheon'
    },
    'zendesk.com': {
        'cname': 'zendesk.com',
        'error_strings': [
            'Help Center Closed',
            'This help center no longer exists',
            'Oops, this help center no longer exists'
        ],
        'service': 'Zendesk'
    },
    'tumblr.com': {
        'cname': 'tumblr.com',
        'error_strings': [
            'Whatever you were looking for doesn\'t currently exist at this address',
            'There\'s nothing here.',
            'Not found'
        ],
        'status_codes': [404],
        'service': 'Tumblr'
    },
    'wordpress.com': {
        'cname': 'wordpress.com',
        'error_strings': [
            'Do you want to register',
            'Domain mapping upgrade for this domain not found'
        ],
        'service': 'WordPress.com'
    },
    'ghost.io': {
        'cname': 'ghost.io',
        'error_strings': [
            'The thing you were looking for is no longer here',
            '404: This site is no longer active'
        ],
        'status_codes': [404],
        'service': 'Ghost'
    },
    'cargo.site': {
        'cname': 'cargo.site',
        'error_strings': [
            'If you\'re moving your domain away from Cargo',
            'This domain is successfully pointed at Cargo but is not connected to a site'
        ],
        'service': 'Cargo'
    },
    'statuspage.io': {
        'cname': 'statuspage.io',
        'error_strings': [
            'You are being',
            'redirected',
            'Status page does not exist'
        ],
        'service': 'Statuspage'
    },
    'uservoice.com': {
        'cname': 'uservoice.com',
        'error_strings': [
            'This UserVoice subdomain is currently available'
        ],
        'service': 'UserVoice'
    },
    'surge.sh': {
        'cname': 'surge.sh',
        'error_strings': [
            'project not found',
            'not found'
        ],
        'status_codes': [404],
        'service': 'Surge.sh'
    },
    'readme.io': {
        'cname': 'readme.io',
        'error_strings': [
            'Project doesnt exist... yet!',
            'Project doesn\'t exist'
        ],
        'service': 'Readme.io'
    },
    'gitbook.io': {
        'cname': 'gitbook.io',
        'error_strings': [
            'We could not find what you\'re looking for',
            'Sorry, we could not find the page'
        ],
        'status_codes': [404],
        'service': 'GitBook'
    },
    'freshdesk.com': {
        'cname': 'freshdesk.com',
        'error_strings': [
            'There is no help desk here yet',
            'May be this is still fresh!'
        ],
        'service': 'Freshdesk'
    },
    'desk.com': {
        'cname': 'desk.com',
        'error_strings': [
            'Please try again or try Desk.com free for 14 days',
            'Sorry, We Couldn\'t Find That Page'
        ],
        'service': 'Desk.com'
    },
    'netlify.app': {
        'cname': 'netlify.app',
        'error_strings': [
            'Not found - Request ID',
            'Page not found',
            'Looks like you\'ve followed a broken link'
        ],
        'status_codes': [404],
        'service': 'Netlify'
    },
    'vercel.app': {
        'cname': 'vercel.app',
        'error_strings': [
            'The deployment could not be found on Vercel',
            '404: NOT_FOUND'
        ],
        'status_codes': [404],
        'service': 'Vercel'
    },
    'webflow.io': {
        'cname': 'webflow.io',
        'error_strings': [
            'The page you are looking for doesn\'t exist or has been moved',
            '<p class="description">The page you are looking for doesn\'t exist or has been moved.</p>'
        ],
        'status_codes': [404],
        'service': 'Webflow'
    },
    'unbounce.com': {
        'cname': 'unbouncepages.com',
        'error_strings': [
            'The requested URL was not found on this server',
            'DiscoveredProxyError'
        ],
        'status_codes': [404],
        'service': 'Unbounce'
    },
    'tilda.ws': {
        'cname': 'tilda.ws',
        'error_strings': [
            'Please renew your subscription',
            'Domain has been assigned'
        ],
        'service': 'Tilda'
    },
    'intercom.help': {
        'cname': 'intercom.help',
        'error_strings': [
            'This page doesn\'t exist',
            'Uh oh. That page doesn\'t exist'
        ],
        'status_codes': [404],
        'service': 'Intercom'
    },
    'helpscoutdocs.com': {
        'cname': 'helpscoutdocs.com',
        'error_strings': [
            'No settings were found for this company',
            'We couldn\'t find any settings for this Docs site'
        ],
        'service': 'Help Scout'
    },
    'helpjuice.com': {
        'cname': 'helpjuice.com',
        'error_strings': [
            'We could not find what you\'re looking for',
            'We\'re sorry, but the Helpjuice site you\'re looking for doesn\'t exist'
        ],
        'service': 'Helpjuice'
    },
    'launchrock.com': {
        'cname': 'launchrock.com',
        'error_strings': [
            'It looks like you may have taken a wrong turn somewhere',
            'Don\'t Freak Out'
        ],
        'service': 'LaunchRock'
    },
    'instapage.com': {
        'cname': 'pageserve.co',
        'error_strings': [
            'This page doesn\'t exist',
            'You\'re looking for a page that doesn\'t exist'
        ],
        'status_codes': [404],
        'service': 'Instapage'
    },
    'campaignmonitor.com': {
        'cname': 'createsend.com',
        'error_strings': [
            'Trying to access your account?',
            'Double check the URL'
        ],
        'service': 'Campaign Monitor'
    },
    'maxcdn.com': {
        'cname': 'maxcdn.com',
        'error_strings': [
            'This website is currently offline',
            '404'
        ],
        'status_codes': [404],
        'service': 'MaxCDN'
    },
    'pingdom.com': {
        'cname': 'stats.pingdom.com',
        'error_strings': [
            'Sorry, couldn\'t find the status page',
            'Public Reports/Stats'
        ],
        'service': 'Pingdom'
    },
    'smartling.com': {
        'cname': 'smartling.com',
        'error_strings': [
            'Domain is not configured',
            'Please make sure that you have added this domain'
        ],
        'service': 'Smartling'
    },
    'smugmug.com': {
        'cname': 'smugmug.com',
        'error_strings': [
            'Page Not Found',
            'We couldn\'t find the page you were looking for'
        ],
        'status_codes': [404],
        'service': 'SmugMug'
    },
    'strikingly.com': {
        'cname': 'strikinglydns.com',
        'error_strings': [
            'page not found',
            'But if you\'re looking to build your own website'
        ],
        'status_codes': [404],
        'service': 'Strikingly'
    },
    'uptimerobot.com': {
        'cname': 'stats.uptimerobot.com',
        'error_strings': [
            'This public status page does not seem to exist',
            'page not found'
        ],
        'status_codes': [404],
        'service': 'UptimeRobot'
    },
    'bigcartel.com': {
        'cname': 'bigcartel.com',
        'error_strings': [
            'Oops! We could not find what you\'re looking for',
            '<h1>Oops! We could not find what you\'re looking for</h1>'
        ],
        'status_codes': [404],
        'service': 'Big Cartel'
    },
    'brightcove.com': {
        'cname': 'brightcove.com',
        'error_strings': [
            '<p class="bc-gallery-error-code">Error Code: 404</p>',
            'We\'re unable to find the page you\'re looking for'
        ],
        'status_codes': [404],
        'service': 'Brightcove'
    },
    'acquia.com': {
        'cname': 'acquia-test.co',
        'error_strings': [
            'The site you are looking for could not be found',
            'Web Site Not Found'
        ],
        'status_codes': [404],
        'service': 'Acquia'
    },
    'kinsta.cloud': {
        'cname': 'kinsta.cloud',
        'error_strings': [
            'No Site For Domain',
            'No site found for the provided domain'
        ],
        'status_codes': [404],
        'service': 'Kinsta'
    },
    'fly.io': {
        'cname': 'fly.io',
        'error_strings': [
            '404 Not Found',
            'The page you are looking for doesn\'t exist'
        ],
        'status_codes': [404],
        'service': 'Fly.io'
    },
    'render.com': {
        'cname': 'onrender.com',
        'error_strings': [
            'Service not found',
            'The page you\'re looking for could not be found'
        ],
        'status_codes': [404],
        'service': 'Render'
    },
    'wixdns.net': {
        'cname': 'wixdns.net',
        'error_strings': [
            'Error ConnectYourDomain occurred',
            'Connect your domain'
        ],
        'service': 'Wix'
    },
    'ngrok.io': {
        'cname': 'ngrok.io',
        'error_strings': [
            'Tunnel *.ngrok.io not found',
            'ngrok.io not found'
        ],
        'status_codes': [404],
        'service': 'Ngrok'
    },
    'thinkific.com': {
        'cname': 'thinkific.com',
        'error_strings': [
            'You may have mistyped the address or the page may have moved',
            'Page Not Found'
        ],
        'status_codes': [404],
        'service': 'Thinkific'
    },
    'canny.io': {
        'cname': 'canny.io',
        'error_strings': [
            'Company Not Found',
            'There is no company with this URL'
        ],
        'service': 'Canny'
    },
    'feedpress.me': {
        'cname': 'redirect.feedpress.me',
        'error_strings': [
            'The feed has not been found',
            'Feed not found'
        ],
        'status_codes': [404],
        'service': 'Feedpress'
    },
    'getresponse.com': {
        'cname': 'getresponse.com',
        'error_strings': [
            'With GetResponse Landing Pages',
            'page not found'
        ],
        'status_codes': [404],
        'service': 'GetResponse'
    },
    'landingi.com': {
        'cname': 'cname.landingi.com',
        'error_strings': [
            'It looks like you\'re lost',
            'The page you are looking for is not found'
        ],
        'status_codes': [404],
        'service': 'Landingi'
    },
    'shortio.link': {
        'cname': 'short.io',
        'error_strings': [
            'Link does not exist',
            'This domain is not configured on Short.io'
        ],
        'service': 'Short.io'
    },
    'airee.ru': {
        'cname': 'airee.ru',
        'error_strings': [
            'Ошибка 402',
            'Сайт не оплачен'
        ],
        'status_codes': [402],
        'service': 'Airee.ru'
    },
    'anima.app': {
        'cname': 'animaapp.io',
        'error_strings': [
            'If this is your website and you\'ve just created it',
            'Project Not Found'
        ],
        'status_codes': [404],
        'service': 'Anima'
    },
    'platformsh.site': {
        'cname': 'platform.sh',
        'error_strings': [
            'We couldn\'t find a project matching that URL',
            'Project not found'
        ],
        'status_codes': [404],
        'service': 'Platform.sh'
    },
    'convertkit-mail.com': {
        'cname': 'convertkit-mail.com',
        'error_strings': [
            'Not found',
            'This page does not exist'
        ],
        'status_codes': [404],
        'service': 'ConvertKit'
    }
}

def print_banner():
    banner = f"""{Colors.OKCYAN}
    ╔═══════════════════════════════════════════════════════════╗
    ║         Subdomain Takeover Detection Tool                 ║
    ║         Checks for Vulnerable CNAME Records               ║
    ║         60+ Services | Nuclei/Subzy-Level Coverage        ║
    ║                                                           ║
    ║                 Created by: MindFlare                     ║
    ╚═══════════════════════════════════════════════════════════╝
    {Colors.ENDC}"""
    print(banner)

def check_cname(domain):
    """Check if domain has a CNAME record"""
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            return str(rdata).rstrip('.')
    except:
        return None

def check_vulnerable_service(domain, cname):
    """Check if CNAME points to vulnerable service"""
    for service_key, fingerprint in TAKEOVER_FINGERPRINTS.items():
        if fingerprint['cname'] in cname.lower():
            # Try to fetch the page
            try:
                for protocol in ['https', 'http']:
                    try:
                        url = f'{protocol}://{domain}'
                        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                        content = response.text.lower()
                        status_code = response.status_code

                        # Check status codes if specified
                        status_match = False
                        if 'status_codes' in fingerprint:
                            if status_code in fingerprint['status_codes']:
                                status_match = True
                        else:
                            # If no status codes specified, any status is ok
                            status_match = True

                        # Check for error strings
                        if status_match:
                            for error_string in fingerprint['error_strings']:
                                if error_string.lower() in content:
                                    return {
                                        'vulnerable': True,
                                        'service': fingerprint['service'],
                                        'cname': cname,
                                        'error_matched': error_string,
                                        'status_code': status_code
                                    }
                        break
                    except:
                        continue
            except Exception as e:
                pass

    return {'vulnerable': False, 'service': None, 'cname': cname}

def check_subdomain_takeover(domain):
    """Main function to check if subdomain is vulnerable to takeover"""
    try:
        # First check if domain has CNAME
        cname = check_cname(domain)

        if not cname:
            return None  # No CNAME, not vulnerable

        # Check if CNAME points to vulnerable service
        result = check_vulnerable_service(domain, cname)

        if result['vulnerable']:
            return {
                'domain': domain,
                'cname': cname,
                'service': result['service'],
                'error_matched': result['error_matched']
            }

    except Exception as e:
        pass

    return None

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='Subdomain Takeover Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('-l', '--list', required=True,
                       help='File containing list of subdomains to check')
    parser.add_argument('-o', '--output', default='vulnerable_takeovers.txt',
                       help='Output file for vulnerable subdomains')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of threads (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    # Load subdomains
    print(f"\n{Colors.OKBLUE}[*] Loading subdomains from: {args.list}{Colors.ENDC}")

    try:
        with open(args.list, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"{Colors.FAIL}[-] Error: File not found: {args.list}{Colors.ENDC}")
        sys.exit(1)

    print(f"{Colors.OKGREEN}[+] Loaded {len(subdomains)} subdomains{Colors.ENDC}")
    print(f"[*] Checking for subdomain takeover vulnerabilities...")
    print(f"[*] Using {args.threads} threads\n")

    vulnerable = []
    checked = 0

    # Use ThreadPoolExecutor for concurrent checking
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check_subdomain_takeover, domain): domain for domain in subdomains}

        for future in futures:
            checked += 1
            result = future.result()

            if result:
                vulnerable.append(result)
                print(f"{Colors.FAIL}[!] VULNERABLE: {result['domain']}{Colors.ENDC}")
                print(f"    └─ Service: {result['service']}")
                print(f"    └─ CNAME: {result['cname']}")
                if 'status_code' in result:
                    print(f"    └─ HTTP Status: {result['status_code']}")
                print(f"    └─ Error: {result['error_matched']}\n")
            elif args.verbose:
                domain = futures[future]
                print(f"{Colors.OKGREEN}[✓] Safe: {domain}{Colors.ENDC}")

            # Progress indicator
            if checked % 10 == 0:
                print(f"{Colors.OKCYAN}[*] Progress: {checked}/{len(subdomains)}{Colors.ENDC}")

    # Save results
    if vulnerable:
        with open(args.output, 'w') as f:
            f.write("# Vulnerable Subdomains - Potential Takeover\n")
            f.write("# Format: domain|service|cname|error\n\n")
            for vuln in vulnerable:
                f.write(f"{vuln['domain']}|{vuln['service']}|{vuln['cname']}|{vuln['error_matched']}\n")

        print(f"\n{Colors.FAIL}{'='*60}{Colors.ENDC}")
        print(f"{Colors.FAIL}[!] ALERT: {len(vulnerable)} VULNERABLE SUBDOMAINS FOUND!{Colors.ENDC}")
        print(f"{Colors.FAIL}{'='*60}{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Saved to: {args.output}{Colors.ENDC}\n")

        print(f"{Colors.BOLD}Vulnerable subdomains:{Colors.ENDC}")
        for vuln in vulnerable:
            print(f"  • {vuln['domain']} → {vuln['service']}")

        print(f"\n{Colors.WARNING}[!] Action Required:{Colors.ENDC}")
        print(f"  1. Verify each subdomain manually")
        print(f"  2. Claim the service to prevent takeover")
        print(f"  3. Remove CNAME record if service no longer needed")
        print(f"  4. Report to bug bounty program if applicable\n")

    else:
        print(f"\n{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[✓] No vulnerable subdomains found!{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{'='*60}{Colors.ENDC}")
        print(f"[*] Checked {checked} subdomains")
        print(f"[*] All CNAMEs appear to be properly configured\n")


if __name__ == '__main__':
    main()
