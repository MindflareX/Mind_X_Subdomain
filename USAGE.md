# Mind_X_Subdomain - Usage Guide

## Quick Start

### 1. Install Dependencies
```bash
pip3 install -r requirements.txt
```

### 2. Make it Executable
```bash
chmod +x Mind_X_Subdomain.py
```

### 3. Basic Usage

#### Run on single domain (no existing data):
```bash
python3 Mind_X_Subdomain.py -d paypal.com -o new_discoveries.txt
```

#### Run with your existing subdomain files:
```bash
python3 Mind_X_Subdomain.py -d paypal.com -f subfinder.txt -o new_discoveries.txt
```

#### Combine multiple existing files:
```bash
cat subfinder.txt cero_domains.txt | sort -u > all_existing.txt
python3 Mind_X_Subdomain.py -d paypal.com -f all_existing.txt -o new_discoveries.txt
```

### 4. Advanced Options

#### Run specific modules only:
```bash
python3 Mind_X_Subdomain.py -d paypal.com -f all_existing.txt -m email cloud javascript
```

#### Adjust rate limiting (slower = more polite):
```bash
python3 Mind_X_Subdomain.py -d paypal.com -f all_existing.txt -r 2.0
```

## Available Modules

- **email**: Mine SPF/DKIM/DMARC records for mail infrastructure
- **reverse_ip**: Find neighbors on same IP addresses
- **cloud**: Enumerate S3, Azure, GCP storage buckets
- **permutations**: Smart DNS permutations based on patterns
- **asn**: ASN enumeration to find IP ranges
- **ct**: Deep Certificate Transparency analysis
- **javascript**: Extract endpoints from JavaScript files
- **acquisitions**: Map acquisition domains (PayPal-specific)
- **historical**: Historical DNS records (requires SecurityTrails API key)

## Configuration (Optional)

Edit `config.json` to add API keys for enhanced features:

### SecurityTrails (Recommended)
1. Sign up at: https://securitytrails.com/app/signup
2. Get free API key (50 queries/month)
3. Add to `config.json`:
```json
{
  "securitytrails_api_key": "YOUR_KEY_HERE"
}
```

### Other Optional APIs
- **Shodan**: https://account.shodan.io/register
- **VirusTotal**: https://www.virustotal.com/gui/join-us
- **GitHub**: https://github.com/settings/tokens (for finding subdomains in code)

## Examples

### Example 1: Full Discovery with Existing Data
```bash
# Combine your existing discoveries
cat subfinder.txt cero_domains.txt | sort -u > known_domains.txt

# Run advanced discovery
python3 Mind_X_Subdomain.py \
  -d paypal.com \
  -f known_domains.txt \
  -o advanced_discoveries.txt \
  -r 1.5
```

### Example 2: Focus on Cloud & JavaScript
```bash
python3 Mind_X_Subdomain.py \
  -d paypal.com \
  -f known_domains.txt \
  -m cloud javascript \
  -o cloud_js_findings.txt
```

### Example 3: Acquisition Hunting
```bash
# Specifically look for acquisition-related domains
python3 Mind_X_Subdomain.py \
  -d paypal.com \
  -f known_domains.txt \
  -m acquisitions permutations \
  -o acquisition_domains.txt
```

## Output

The tool will:
1. Print newly discovered domains in GREEN as they're found
2. Show cloud bucket discoveries in YELLOW
3. Save all new discoveries to the output file
4. Display summary at the end

## Tips for Bug Bounty

1. **Combine with your existing data** - This tool builds on what you already found
2. **Run regularly** - Infrastructure changes, new domains appear
3. **Focus on acquisitions** - Often have legacy/forgotten systems
4. **Check cloud buckets carefully** - May contain sensitive data
5. **Analyze JavaScript thoroughly** - Often reveals internal APIs
6. **Look for patterns** - staging, dev, sandbox, internal, admin, etc.

## Rate Limiting

- Default rate limit: 1 second between requests
- Adjust with `-r` flag based on target:
  - `-r 0.5`: Faster (use on your own infrastructure)
  - `-r 1.0`: Default (balanced)
  - `-r 2.0`: Slower (more polite for bug bounty)

## Troubleshooting

### "Module not found" error
```bash
pip3 install -r requirements.txt
```

### DNS resolver errors
```bash
# Install system DNS tools
sudo apt-get install dnsutils
```

### Rate limiting issues
Increase delay with `-r 3.0` or higher

## Next Steps

After running this tool:

1. **Validate findings**: Test HTTP/HTTPS access
```bash
cat new_discoveries.txt | httpx -o alive.txt
```

2. **Screenshot alive hosts**:
```bash
cat alive.txt | aquatone
```

3. **Port scan interesting targets**:
```bash
nmap -iL interesting_hosts.txt -oA scan_results
```

4. **Look for patterns** in discoveries to find more
5. **Test for vulnerabilities** on newly discovered assets
